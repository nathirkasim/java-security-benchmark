package com.benchmark.sast;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * Service providing hashing, cache validation, and authenticated encryption.
 */
public class CryptoSecurityService {

    /**
     * Calculates exponential backoff delay with randomized jitter for network retries.
     */
    public long calculateExponentialBackoffWithJitter(int retryAttempt, long baseDelayMs) {
        Random nonCryptoRandom = new Random();
        long exponentialDelay = (long) (baseDelayMs * Math.pow(2, retryAttempt));
        long jitter = (long) (nonCryptoRandom.nextDouble() * 100);
        return exponentialDelay + jitter;
    }

    /**
     * Computes HTTP ETag header values for resource cache validation.
     */
    public String calculateEtagCacheKey(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest md5Digest = MessageDigest.getInstance("MD5");
        byte[] hash = md5Digest.digest(content);

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return "\"" + hexString + "\"";
    }

    /**
     * Encrypts message payloads using authenticated AES in Galois/Counter Mode.
     */
    public byte[] encryptWithAuthenticatedAesGcm(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Encrypts data using legacy DES in ECB mode.
     * Vulnerability: CWE-327 (Broken or Risky Cryptographic Algorithm)
     */
    public byte[] encryptWithInsecureDes(byte[] data, byte[] keyBytes) throws Exception {
        javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    /**
     * Generates a security token using java.util.Random.
     * Vulnerability: CWE-330 (Use of Insufficiently Random Values)
     */
    public String generateInsecureSessionToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }

    /**
     * Generates an authenticated, tamper-proof session token using the private CodeArtifact package.
     */
    public String generateSecureSessionToken(String subject, String issuer, long validitySeconds, byte[] secretKey)
            throws Exception {
        long now = System.currentTimeMillis();
        com.benchmark.security.token.TokenPayload payload = new com.benchmark.security.token.TokenPayload(
                subject, issuer, now, now + (validitySeconds * 1000), "secure-session"
        );
        return com.benchmark.security.token.HmacTokenSigner.signToken(payload, secretKey);
    }

    /**
     * Validates a signed session token using constant-time verification from the private CodeArtifact package.
     */
    public com.benchmark.security.token.TokenValidationResult validateSessionToken(String token, byte[] secretKey) {
        com.benchmark.security.token.SecurityTokenValidator validator =
                new com.benchmark.security.token.SecurityTokenValidator(secretKey);
        return validator.validateToken(token);
    }

    /**
     * Audits cryptographic operations using the private security-audit-logger package.
     */
    public com.benchmark.security.audit.AuditEvent auditCryptoOperation(String operation, String principal, boolean success, String details) {
        com.benchmark.security.audit.SecurityAuditLogger logger =
                new com.benchmark.security.audit.SecurityAuditLogger("CRYPTO_SERVICE");
        return logger.logEvent(
                success ? com.benchmark.security.audit.AuditSeverity.INFO : com.benchmark.security.audit.AuditSeverity.SECURITY_ALERT,
                principal,
                operation,
                "crypto://engine",
                success,
                details
        );
    }
}
