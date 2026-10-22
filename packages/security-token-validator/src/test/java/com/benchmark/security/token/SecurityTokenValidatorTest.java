package com.benchmark.security.token;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;

public class SecurityTokenValidatorTest {

    private byte[] secretKey;
    private SecurityTokenValidator validator;

    @Before
    public void setUp() {
        secretKey = "super-secure-enterprise-secret-key-32b!".getBytes(StandardCharsets.UTF_8);
        validator = new SecurityTokenValidator(secretKey);
    }

    @Test
    public void testValidTokenPasses() throws Exception {
        long now = System.currentTimeMillis();
        TokenPayload payload = new TokenPayload("admin-user", "auth-service", now, now + 60000, "read,write");
        String token = HmacTokenSigner.signToken(payload, secretKey);

        TokenValidationResult result = validator.validateToken(token, now + 1000);
        Assert.assertTrue(result.isValid());
        Assert.assertNotNull(result.getPayload());
        Assert.assertEquals("admin-user", result.getPayload().getSubject());
        Assert.assertEquals("read,write", result.getPayload().getScope());
    }

    @Test
    public void testTamperedSignatureFails() throws Exception {
        long now = System.currentTimeMillis();
        TokenPayload payload = new TokenPayload("user-1", "auth-service", now, now + 60000, "read");
        String token = HmacTokenSigner.signToken(payload, secretKey);

        // Tamper with signature
        String tamperedToken = token.substring(0, token.length() - 2) + "aa";
        TokenValidationResult result = validator.validateToken(tamperedToken, now + 1000);
        Assert.assertFalse(result.isValid());
        Assert.assertTrue(result.getErrorMessage().contains("signature"));
    }

    @Test
    public void testExpiredTokenFails() throws Exception {
        long now = System.currentTimeMillis();
        TokenPayload payload = new TokenPayload("user-2", "auth-service", now - 10000, now - 1000, "read");
        String token = HmacTokenSigner.signToken(payload, secretKey);

        TokenValidationResult result = validator.validateToken(token, now);
        Assert.assertFalse(result.isValid());
        Assert.assertTrue(result.getErrorMessage().contains("expired"));
    }

    @Test
    public void testVulnerableSignatureBypass() {
        long now = System.currentTimeMillis();
        TokenPayload payload = new TokenPayload("bypassed-admin", "auth-service", now, now + 60000, "admin:all");
        String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.serialize().getBytes(StandardCharsets.UTF_8));
        String unsignedToken = encodedPayload + ".none";

        TokenValidationResult result = validator.validateTokenInsecureSignatureBypass(unsignedToken);
        Assert.assertTrue(result.isValid());
        Assert.assertEquals("bypassed-admin", result.getPayload().getSubject());
    }

    @Test
    public void testVulnerableTimingComparison() {
        byte[] a = new byte[]{1, 2, 3, 4};
        byte[] b = new byte[]{1, 2, 3, 4};
        byte[] c = new byte[]{1, 2, 3, 5};
        Assert.assertTrue(validator.verifySignatureWithTimingVulnerability(a, b));
        Assert.assertFalse(validator.verifySignatureWithTimingVulnerability(a, c));
    }

    @Test
    public void testVulnerableWeakMd5Token() throws Exception {
        String token = validator.generateWeakMd5Token("test-user", "secret");
        Assert.assertNotNull(token);
        Assert.assertEquals(32, token.length()); // MD5 produces 32 hex chars
    }

    @Test
    public void testVulnerableDeserialization() throws Exception {
        String testString = "TestUntrustedPayload";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(testString);
        }
        Object result = validator.deserializeUntrustedObjectToken(baos.toByteArray());
        Assert.assertEquals(testString, result);
    }
}
