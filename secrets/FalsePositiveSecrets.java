package com.benchmark.falsepositives.secrets;

import java.util.UUID;

/**
 * Secret Scanning False Positive Benchmark
 * Target Scanners: Gitleaks, TruffleHog, GitHub Secret Scanning, Wiz Secret Scanner
 * Reference CWE: CWE-798 (Use of Hard-coded Credentials)
 */
public class FalsePositiveSecrets {

    // =========================================================================
    // TRAP 1: High-Entropy Non-Secrets (Hashes, Encodings, UUIDs)
    // Scanner Mistake: Shannon entropy detectors flag random-looking strings.
    // Ground Truth: FALSE POSITIVE. Hashes and Base64 assets contain zero confidential credentials.
    // =========================================================================

    // Expected SHA-256 hash of an empty file (common unit test assert constant)
    public static final String EMPTY_FILE_SHA256 =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // Base64-encoded 1x1 transparent GIF image asset
    public static final String INLINE_1PX_TRANSPARENT_GIF_BASE64 =
            "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

    // Standard UUID RFC 4122 v4 test fixture
    public static final UUID MOCK_TRACE_CORRELATION_ID =
            UUID.fromString("c73bcdcc-2669-4bf6-81d3-e4ae73fb11fd");

    // =========================================================================
    // TRAP 2: Variable Names with Secret Keywords Holding Non-Secret Constants
    // Scanner Mistake: Naive regex rules (e.g. `password\s*=\s*['"][^'"]+['"]`) match the variable name.
    // Ground Truth: FALSE POSITIVE. URLs, HTTP header prefixes, and schema constants are not secrets.
    // =========================================================================

    public static final String PASSWORD_RESET_REDIRECT_URI =
            "https://idp.example.com/auth/realms/production/protocol/openid-connect/forgot-password";

    public static final String TOKEN_AUTHENTICATION_HEADER_PREFIX =
            "Bearer ";

    public static final String API_KEY_QUERY_PARAMETER_NAME =
            "x-api-key";

    // =========================================================================
    // TRAP 3: RFC-compliant / AWS-documented Example Placeholders
    // Scanner Mistake: Rule matches AWS key prefix `AKIA...` without checking for dummy example suffix.
    // Ground Truth: FALSE POSITIVE. Canonical AWS documentation placeholder key.
    // =========================================================================
    public static final String AWS_DOCUMENTATION_EXAMPLE_KEY =
            "AKIAIOSFODNN7EXAMPLE";
}
