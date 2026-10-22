package com.benchmark.security.token;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Enterprise token validator with constant-time signature comparison to prevent timing attacks.
 */
public class SecurityTokenValidator {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private final byte[] secretKey;

    public SecurityTokenValidator(byte[] secretKey) {
        if (secretKey == null || secretKey.length == 0) {
            throw new IllegalArgumentException("Secret key cannot be null or empty");
        }
        this.secretKey = secretKey.clone();
    }

    /**
     * Validates token signature, structure, and expiration.
     */
    public TokenValidationResult validateToken(String token) {
        return validateToken(token, System.currentTimeMillis());
    }

    /**
     * Validates token against a specific reference time.
     */
    public TokenValidationResult validateToken(String token, long referenceEpochMs) {
        if (token == null || token.trim().isEmpty()) {
            return TokenValidationResult.failure("Token is null or empty");
        }

        String[] parts = token.split("\\.");
        if (parts.length != 2) {
            return TokenValidationResult.failure("Invalid token structure: expected 2 segments");
        }

        String encodedPayload = parts[0];
        String encodedSignature = parts[1];

        byte[] expectedSignatureBytes;
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, HMAC_ALGORITHM);
            mac.init(keySpec);
            expectedSignatureBytes = mac.doFinal(encodedPayload.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            return TokenValidationResult.failure("Internal crypto error during signature verification");
        }

        byte[] actualSignatureBytes;
        try {
            actualSignatureBytes = Base64.getUrlDecoder().decode(encodedSignature);
        } catch (IllegalArgumentException e) {
            return TokenValidationResult.failure("Malformed signature base64 encoding");
        }

        // Constant-time comparison to prevent side-channel timing attacks (CWE-208)
        if (!MessageDigest.isEqual(expectedSignatureBytes, actualSignatureBytes)) {
            return TokenValidationResult.failure("Invalid token signature: verification failed");
        }

        // Decode payload
        byte[] payloadBytes;
        try {
            payloadBytes = Base64.getUrlDecoder().decode(encodedPayload);
        } catch (IllegalArgumentException e) {
            return TokenValidationResult.failure("Malformed payload base64 encoding");
        }

        TokenPayload payload;
        try {
            String serialized = new String(payloadBytes, StandardCharsets.UTF_8);
            payload = TokenPayload.deserialize(serialized);
        } catch (Exception e) {
            return TokenValidationResult.failure("Failed to deserialize token payload: " + e.getMessage());
        }

        if (payload.isExpired(referenceEpochMs)) {
            return TokenValidationResult.failure("Token expired at " + payload.getExpiresAtEpochMs()
                    + ", current time is " + referenceEpochMs);
        }

        return TokenValidationResult.success(payload);
    }
}
