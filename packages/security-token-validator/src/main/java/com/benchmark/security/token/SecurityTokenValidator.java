package com.benchmark.security.token;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

/**
 * Enterprise token validator containing both hardened production methods
 * and intentionally vulnerable routines for SAST, SCA, and AST scanner evaluation.
 */
public class SecurityTokenValidator {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * Vulnerability: CWE-798 (Use of Hard-coded Credentials)
     */
    public static final String HARDCODED_FALLBACK_SECRET = "insecure_jwt_token_fallback_master_secret_key_2026!";

    private final byte[] secretKey;

    public SecurityTokenValidator() {
        this(HARDCODED_FALLBACK_SECRET.getBytes(StandardCharsets.UTF_8));
    }

    public SecurityTokenValidator(byte[] secretKey) {
        if (secretKey == null || secretKey.length == 0) {
            throw new IllegalArgumentException("Secret key cannot be null or empty");
        }
        this.secretKey = secretKey.clone();
    }

    /**
     * Hardened token validation using constant-time signature comparison.
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

    /**
     * Vulnerability: CWE-347 (Improper Verification of Cryptographic Signature)
     * Signature bypass when "alg=none" is present or signature is blank or bypassed.
     */
    public TokenValidationResult validateTokenInsecureSignatureBypass(String token) {
        if (token == null || token.isEmpty()) {
            return TokenValidationResult.failure("Token is empty");
        }

        String[] parts = token.split("\\.");
        String encodedPayload = parts[0];

        // INSECURE: If signature segment is missing or "none", signature check is skipped
        if (parts.length == 1 || (parts.length == 2 && ("none".equalsIgnoreCase(parts[1]) || parts[1].isEmpty()))) {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(encodedPayload);
            TokenPayload payload = TokenPayload.deserialize(new String(payloadBytes, StandardCharsets.UTF_8));
            return TokenValidationResult.success(payload);
        }

        return validateToken(token);
    }

    /**
     * Vulnerability: CWE-208 (Observable Timing Discrepancy)
     * Uses non-constant time byte-by-byte comparison with early return, enabling timing attacks.
     */
    public boolean verifySignatureWithTimingVulnerability(byte[] expectedSignature, byte[] actualSignature) {
        if (expectedSignature == null || actualSignature == null) {
            return false;
        }
        if (expectedSignature.length != actualSignature.length) {
            return false;
        }
        // Insecure: Early return on mismatch leaks the index of the first mismatching byte
        for (int i = 0; i < expectedSignature.length; i++) {
            if (expectedSignature[i] != actualSignature[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Vulnerability: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
     * Generates a token hash using weak MD5 digest.
     */
    public String generateWeakMd5Token(String subject, String secret) throws GeneralSecurityException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] digest = md5.digest((subject + ":" + secret).getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Vulnerability: CWE-502 (Deserialization of Untrusted Data)
     * Deserializes untrusted byte stream using standard ObjectInputStream without filtering.
     */
    public Object deserializeUntrustedObjectToken(byte[] serializedBytes) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(serializedBytes);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return ois.readObject();
        }
    }

    /**
     * Vulnerability: CWE-330 (Use of Insufficiently Random Values)
     * Generates token nonce with non-cryptographic java.util.Random.
     */
    public long generateInsecureRandomNonce() {
        Random random = new Random();
        return random.nextLong();
    }
}
