package com.benchmark.security.token;

/**
 * Result of token validation containing status, failure reason, and decoded payload.
 */
public class TokenValidationResult {
    private final boolean valid;
    private final String errorMessage;
    private final TokenPayload payload;

    private TokenValidationResult(boolean valid, String errorMessage, TokenPayload payload) {
        this.valid = valid;
        this.errorMessage = errorMessage;
        this.payload = payload;
    }

    public static TokenValidationResult success(TokenPayload payload) {
        return new TokenValidationResult(true, null, payload);
    }

    public static TokenValidationResult failure(String errorMessage) {
        return new TokenValidationResult(false, errorMessage, null);
    }

    public boolean isValid() {
        return valid;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public TokenPayload getPayload() {
        return payload;
    }

    @Override
    public String toString() {
        return valid ? "SUCCESS(subject=" + payload.getSubject() + ")" : "FAILED(" + errorMessage + ")";
    }
}
