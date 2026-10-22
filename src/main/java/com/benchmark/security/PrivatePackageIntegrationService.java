package com.benchmark.security;

import com.benchmark.security.audit.AuditEvent;
import com.benchmark.security.audit.AuditSeverity;
import com.benchmark.security.audit.SecurityAuditLogger;
import com.benchmark.security.token.HmacTokenSigner;
import com.benchmark.security.token.SecurityTokenValidator;
import com.benchmark.security.token.TokenPayload;
import com.benchmark.security.token.TokenValidationResult;

import java.security.GeneralSecurityException;
import java.util.List;

/**
 * Service integrating private security packages hosted on AWS CodeArtifact:
 * 1. com.benchmark.security:security-audit-logger (CRLF-safe audit logging)
 * 2. com.benchmark.security:security-token-validator (Constant-time HMAC token validation)
 */
public class PrivatePackageIntegrationService {

    private final SecurityAuditLogger auditLogger;

    public PrivatePackageIntegrationService() {
        this("BENCHMARK_CORE");
    }

    public PrivatePackageIntegrationService(String subsystemName) {
        this.auditLogger = new SecurityAuditLogger(subsystemName);
    }

    /**
     * Issues an authenticated token using the private HmacTokenSigner library.
     */
    public String issueSignedToken(String subject, String issuer, long validitySeconds, String scope, byte[] secretKey)
            throws GeneralSecurityException {
        long now = System.currentTimeMillis();
        long expiresAt = now + (validitySeconds * 1000);

        TokenPayload payload = new TokenPayload(subject, issuer, now, expiresAt, scope);
        String token = HmacTokenSigner.signToken(payload, secretKey);

        auditLogger.logEvent(
                AuditSeverity.INFO,
                issuer,
                "ISSUE_TOKEN",
                "token://session/" + subject,
                true,
                "Token successfully generated for subject " + subject + " with validity " + validitySeconds + "s"
        );

        return token;
    }

    /**
     * Authenticates a bearer token using the private SecurityTokenValidator library and
     * automatically audits the outcome to prevent unmonitored authentication failures.
     */
    public TokenValidationResult authenticateAndAudit(String token, byte[] secretKey, String resource) {
        SecurityTokenValidator validator = new SecurityTokenValidator(secretKey);
        TokenValidationResult result = validator.validateToken(token);

        if (result.isValid()) {
            auditLogger.logEvent(
                    AuditSeverity.INFO,
                    result.getPayload().getSubject(),
                    "ACCESS_GRANTED",
                    resource,
                    true,
                    "Access allowed for scope " + result.getPayload().getScope()
            );
        } else {
            auditLogger.logEvent(
                    AuditSeverity.SECURITY_ALERT,
                    "unauthenticated",
                    "ACCESS_DENIED",
                    resource,
                    false,
                    "Token validation failed: " + result.getErrorMessage()
            );
        }

        return result;
    }

    /**
     * Logs an arbitrary security event via the private audit logger package.
     */
    public AuditEvent auditOperation(AuditSeverity severity, String principal, String action,
                                     String resource, boolean success, String message) {
        return auditLogger.logEvent(severity, principal, action, resource, success, message);
    }

    /**
     * Retrieves the audit trail recorded by the private audit logger.
     */
    public List<AuditEvent> getAuditHistory() {
        return auditLogger.getAuditTrail();
    }

    /**
     * Returns the underlying audit logger instance.
     */
    public SecurityAuditLogger getAuditLogger() {
        return auditLogger;
    }
}
