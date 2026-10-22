package com.benchmark.security.token;

/**
 * Parsed payload of a signed security token.
 */
public class TokenPayload {
    private final String subject;
    private final String issuer;
    private final long issuedAtEpochMs;
    private final long expiresAtEpochMs;
    private final String scope;

    public TokenPayload(String subject, String issuer, long issuedAtEpochMs, long expiresAtEpochMs, String scope) {
        this.subject = subject != null ? subject : "";
        this.issuer = issuer != null ? issuer : "";
        this.issuedAtEpochMs = issuedAtEpochMs;
        this.expiresAtEpochMs = expiresAtEpochMs;
        this.scope = scope != null ? scope : "default";
    }

    public String getSubject() {
        return subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public long getIssuedAtEpochMs() {
        return issuedAtEpochMs;
    }

    public long getExpiresAtEpochMs() {
        return expiresAtEpochMs;
    }

    public String getScope() {
        return scope;
    }

    public boolean isExpired(long currentEpochMs) {
        return currentEpochMs > expiresAtEpochMs;
    }

    public String serialize() {
        return String.format("%s:%s:%d:%d:%s",
                escape(subject), escape(issuer), issuedAtEpochMs, expiresAtEpochMs, escape(scope));
    }

    public static TokenPayload deserialize(String serialized) {
        if (serialized == null) {
            throw new IllegalArgumentException("Serialized payload cannot be null");
        }
        String[] parts = serialized.split(":", 5);
        if (parts.length < 5) {
            throw new IllegalArgumentException("Invalid serialized token payload format");
        }
        String subject = unescape(parts[0]);
        String issuer = unescape(parts[1]);
        long issuedAt = Long.parseLong(parts[2]);
        long expiresAt = Long.parseLong(parts[3]);
        String scope = unescape(parts[4]);

        return new TokenPayload(subject, issuer, issuedAt, expiresAt, scope);
    }

    private static String escape(String s) {
        return s.replace("%", "%25").replace(":", "%3A");
    }

    private static String unescape(String s) {
        return s.replace("%3A", ":").replace("%25", "%");
    }
}
