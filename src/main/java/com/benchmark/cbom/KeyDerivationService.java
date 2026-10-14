package com.benchmark.cbom;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Service providing password-based key derivation and entropy generation.
 */
public class KeyDerivationService {

    private static final int ITERATION_COUNT = 310000;
    private static final int KEY_LENGTH_BITS = 256;

    /**
     * Derives cryptographic keys using PBKDF2 with SHA-512.
     */
    public byte[] deriveKeyWithHardenedPbkdf2(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * Generates cryptographic nonces using native strong entropy.
     */
    public byte[] generateCryptographicNonce(int length) throws NoSuchAlgorithmException {
        SecureRandom strongCsprng = SecureRandom.getInstanceStrong();
        byte[] nonce = new byte[length];
        strongCsprng.nextBytes(nonce);
        return nonce;
    }
}
