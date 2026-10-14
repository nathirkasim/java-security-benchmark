package com.benchmark.falsepositives.cbom;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * CBOM (Cryptography Bill of Materials) False Positive Benchmark
 * Target: CycloneDX 1.6 CBOM scanners & Quantum-Readiness Analyzers
 *
 * Scanners scanning for CBOM algorithms often naively flag:
 * 1. Hybrid KEM schemes as purely non-quantum compliant.
 * 2. High-iteration PBKDF2 configurations as "legacy weak password hashing".
 * 3. SecureRandom usage lacking explicit strong algorithm designation.
 */
public class CbomAuditCases {

    private static final int OWASP_RECOMMENDED_ITERATIONS = 310000;
    private static final int KEY_LENGTH_BITS = 256;

    /**
     * TRAP 1: OWASP-Hardened PBKDF2 Key Derivation
     * Scanner Mistake: Flags PBKDF2 under "Legacy/Deprecate Hash" rules without inspecting iteration count.
     * Ground Truth: FALSE POSITIVE. Configured with 310,000 iterations using HMAC-SHA512,
     * fully adhering to modern OWASP / NIST SP 800-132 password storage guidelines.
     */
    public byte[] deriveKeyWithHardenedPbkdf2(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, OWASP_RECOMMENDED_ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * TRAP 2: Native OS Strong CSPRNG
     * Scanner Mistake: CBOM analyzer flags missing entropy configuration.
     * Ground Truth: FALSE POSITIVE. Explicitly uses native OS-provided strong entropy source via getInstanceStrong().
     */
    public byte[] generateCryptographicNonce(int length) throws NoSuchAlgorithmException {
        SecureRandom strongCsprng = SecureRandom.getInstanceStrong();
        byte[] nonce = new byte[length];
        strongCsprng.nextBytes(nonce);
        return nonce;
    }
}
