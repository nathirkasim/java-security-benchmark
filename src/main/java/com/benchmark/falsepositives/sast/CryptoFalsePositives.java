package com.benchmark.falsepositives.sast;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * SAST & CBOM False Positive Benchmark - Cryptography and Randomness
 * Reference Rules:
 *  - SonarQube: java:S2245 (Using pseudorandom number generators (PRNGs) is security-sensitive)
 *  - SonarQube: java:S4790 (Weak hashing algorithms should not be used)
 *  - SonarQube: java:S5542 (Encryption algorithms should be used with secure mode and padding scheme)
 *  - Wiz / Semgrep: weak-crypto, md5-insecure
 *  - CWE-327, CWE-328, CWE-338
 */
public class CryptoFalsePositives {

    /**
     * TRAP 1: Non-Security PRNG Usage (Network Backoff Jitter)
     * Scanner Mistake: Flags java.util.Random unconditionally under Rule S2245 (CWE-338),
     * assuming all random numbers are security tokens or session IDs.
     * Ground Truth: FALSE POSITIVE. Random is used solely to add randomized jitter in network retry logic
     * to prevent the "thundering herd" problem. No security credentials or crypto keys are involved.
     */
    public long calculateExponentialBackoffWithJitter(int retryAttempt, long baseDelayMs) {
        Random nonCryptoRandom = new Random();
        long exponentialDelay = (long) (baseDelayMs * Math.pow(2, retryAttempt));
        long jitter = (long) (nonCryptoRandom.nextDouble() * 100);
        return exponentialDelay + jitter;
    }

    /**
     * TRAP 2: Non-Cryptographic Checksum / Cache Key Generation (MD5 / SHA-1)
     * Scanner Mistake: Flags `MessageDigest.getInstance("MD5")` as insecure cryptographic hashing (CWE-328).
     * Ground Truth: FALSE POSITIVE. Used purely for HTTP ETag content-caching or local file deduplication,
     * not for digital signatures, password storage, or integrity authentication.
     */
    public String calculateEtagCacheKey(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest md5Digest = MessageDigest.getInstance("MD5");
        byte[] hash = md5Digest.digest(content);

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return "\"" + hexString + "\""; // Standard HTTP ETag format
    }

    /**
     * TRAP 3: AES-GCM Authenticated Encryption with "NoPadding"
     * Scanner Mistake: Naive scanners regex-match the string `"NoPadding"` and trigger rules like
     * `RSA_NO_PADDING` or unpadded block cipher alerts.
     * Ground Truth: FALSE POSITIVE. AES-GCM (Galois/Counter Mode) provides Authenticated Encryption
     * with Associated Data (AEAD). It operates in counter mode and does not use or need PKCS padding.
     * The standard JCE transformation string is strictly `AES/GCM/NoPadding`.
     */
    public byte[] encryptWithAuthenticatedAesGcm(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext);
    }
}
