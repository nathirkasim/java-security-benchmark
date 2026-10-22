package com.benchmark.security.token;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

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
}
