package com.benchmark.security.audit;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

public class SecurityAuditLoggerTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private SecurityAuditLogger logger;

    @Before
    public void setUp() {
        logger = new SecurityAuditLogger("AUTH_SERVICE");
    }

    @Test
    public void testSanitizationNeutralizesCrlf() {
        String tainted = "admin\r\nCRITICAL: Fake log entry injected\nAnother line";
        String clean = SecurityAuditLogger.sanitize(tainted);
        Assert.assertFalse(clean.contains("\r"));
        Assert.assertFalse(clean.contains("\n"));
        Assert.assertTrue(clean.contains("admin__CRITICAL: Fake log entry injected_Another line"));
    }

    @Test
    public void testLogEventRecordCreation() {
        AuditEvent event = logger.logEvent(
                AuditSeverity.CRITICAL,
                "attacker\r\n",
                "LOGIN_ATTEMPT",
                "/api/v1/auth",
                false,
                "Password spray detected\nIP=10.0.0.1"
        );

        Assert.assertNotNull(event);
        Assert.assertNotNull(event.getEventId());
        Assert.assertEquals(AuditSeverity.CRITICAL, event.getSeverity());
        Assert.assertFalse(event.getPrincipal().contains("\r"));
        Assert.assertFalse(event.getMessage().contains("\n"));

        List<AuditEvent> trail = logger.getAuditTrail();
        Assert.assertEquals(1, trail.size());
        Assert.assertEquals(event.getEventId(), trail.get(0).getEventId());
    }

    @Test
    public void testVulnerableLogRawEventUnsanitized() {
        // Exercise the vulnerable log injection method
        logger.logRawEventUnsanitized("admin\r\nINJECTED", "AUTH_BYPASS", "Forged log event\r\n");
    }

    @Test
    public void testVulnerableCredentialLeakLogging() {
        logger.logCredentialLeak("superadmin", "Password123!", "eyJhbGci...", "api_key_secret_12345");
    }

    @Test
    public void testVulnerableFileExportPathTraversal() throws IOException {
        File dir = tempFolder.newFolder("logs");
        File exported = logger.exportAuditLogToFile(dir.getAbsolutePath(), "audit.log", "audit entry");
        Assert.assertTrue(exported.exists());
        Assert.assertEquals("audit entry", Files.readString(exported.toPath()));
    }

    @Test
    public void testText4ShellInterpolation() {
        String rendered = logger.renderTemplateText4Shell("Audit message for user ${base64Decoder:YWRtaW4=}");
        Assert.assertTrue(rendered.contains("admin"));
    }
}
