package com.benchmark;

import com.benchmark.sast.CryptoSecurityService;
import com.benchmark.security.PrivatePackageIntegrationService;
import com.benchmark.security.audit.AuditEvent;
import com.benchmark.security.audit.AuditSeverity;
import com.benchmark.security.token.TokenValidationResult;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class PrivatePackageIntegrationTest {

    private PrivatePackageIntegrationService service;
    private byte[] secretKey;

    @Before
    public void setUp() {
        service = new PrivatePackageIntegrationService("SECURITY_TEST_SUITE");
        secretKey = "benchmark-super-secret-key-for-tests-32b!".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void testPrivatePackageTokenIssuanceAndValidation() throws Exception {
        // 1. Issue signed token via private package
        String token = service.issueSignedToken("alice-ops", "identity-provider", 300, "read:audit,write:logs", secretKey);
        Assert.assertNotNull(token);
        Assert.assertTrue(token.contains("."));

        // 2. Validate token and audit access
        TokenValidationResult result = service.authenticateAndAudit(token, secretKey, "/api/v1/protected-resource");
        Assert.assertTrue("Token should be valid", result.isValid());
        Assert.assertEquals("alice-ops", result.getPayload().getSubject());
        Assert.assertEquals("read:audit,write:logs", result.getPayload().getScope());

        // 3. Verify audit history recorded both events
        List<AuditEvent> auditHistory = service.getAuditHistory();
        Assert.assertEquals(2, auditHistory.size());

        AuditEvent issueEvent = auditHistory.get(0);
        Assert.assertEquals("ISSUE_TOKEN", issueEvent.getAction());
        Assert.assertTrue(issueEvent.isSuccess());

        AuditEvent accessEvent = auditHistory.get(1);
        Assert.assertEquals("ACCESS_GRANTED", accessEvent.getAction());
        Assert.assertEquals("alice-ops", accessEvent.getPrincipal());
        Assert.assertTrue(accessEvent.isSuccess());
    }

    @Test
    public void testPrivatePackageTamperDetectionAndSecurityAlert() throws Exception {
        String token = service.issueSignedToken("bob-dev", "identity-provider", 300, "read:users", secretKey);

        // Tamper with signature
        String tamperedToken = token.substring(0, token.length() - 4) + "zzzz";

        TokenValidationResult result = service.authenticateAndAudit(tamperedToken, secretKey, "/admin/system");
        Assert.assertFalse("Tampered token must fail validation", result.isValid());
        Assert.assertNotNull(result.getErrorMessage());

        // Verify that failed access triggered a SECURITY_ALERT audit event
        List<AuditEvent> history = service.getAuditHistory();
        AuditEvent alertEvent = history.get(history.size() - 1);
        Assert.assertEquals(AuditSeverity.SECURITY_ALERT, alertEvent.getSeverity());
        Assert.assertEquals("ACCESS_DENIED", alertEvent.getAction());
        Assert.assertFalse(alertEvent.isSuccess());
    }

    @Test
    public void testCryptoSecurityServiceIntegrationWithPrivatePackages() throws Exception {
        CryptoSecurityService crypto = new CryptoSecurityService();

        // Call private package via CryptoSecurityService
        String sessionToken = crypto.generateSecureSessionToken("service-account", "auth-hub", 120, secretKey);
        Assert.assertNotNull(sessionToken);

        TokenValidationResult validationResult = crypto.validateSessionToken(sessionToken, secretKey);
        Assert.assertTrue(validationResult.isValid());
        Assert.assertEquals("service-account", validationResult.getPayload().getSubject());

        AuditEvent audit = crypto.auditCryptoOperation("AES_GCM_ENCRYPT", "service-account", true, "Payload encrypted");
        Assert.assertNotNull(audit);
        Assert.assertEquals(AuditSeverity.INFO, audit.getSeverity());
        Assert.assertEquals("AES_GCM_ENCRYPT", audit.getAction());
    }
}
