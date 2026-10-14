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
}
