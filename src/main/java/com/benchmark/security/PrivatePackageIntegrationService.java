package com.benchmark.security;

import com.benchmark.security.audit.AuditEvent;
import com.benchmark.security.audit.AuditSeverity;
import com.benchmark.security.audit.SecurityAuditLogger;
import com.benchmark.security.token.HmacTokenSigner;
import com.benchmark.security.token.SecurityTokenValidator;
import com.benchmark.security.token.TokenPayload;
import com.benchmark.security.token.TokenValidationResult;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

/**
 * Service integrating private security packages hosted on AWS CodeArtifact:
 * 1. com.benchmark.security:security-audit-logger (v1.1.0)
 * 2. com.benchmark.security:security-token-validator (v1.1.0)
 *
 * Exposes both production routines and intentionally vulnerable entrypoints
 * designed for AST, SAST, SCA, and SBOM security scanning validation.
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

    // =========================================================================
    // Vulnerable Package Integration Entrypoints (for Security Tool Evaluation)
    // =========================================================================

    /**
     * Calls vulnerable CWE-117 (Log Injection) in private package security-audit-logger.
     */
    public void triggerVulnerableLogInjection(String principal, String action, String untrustedMessage) {
        auditLogger.logRawEventUnsanitized(principal, action, untrustedMessage);
    }

    /**
     * Calls vulnerable CWE-532 (Cleartext Credential Leakage) in private package security-audit-logger.
     */
    public void triggerCredentialLeakLogging(String username, String password, String token, String apiKey) {
        auditLogger.logCredentialLeak(username, password, token, apiKey);
    }

    /**
     * Calls vulnerable CWE-22 (Path Traversal File Write) in private package security-audit-logger.
     */
    public File triggerPathTraversalExport(String targetDir, String filename, String content) throws IOException {
        return auditLogger.exportAuditLogToFile(targetDir, filename, content);
    }

    /**
     * Calls vulnerable CWE-89 (SQL Injection) in private package security-audit-logger.
     */
    public void triggerSqlInjectionPersistence(Connection conn, String eventId, String principal, String action, String message)
            throws SQLException {
        auditLogger.persistAuditRecordSqlInjection(conn, eventId, principal, action, message);
    }

    /**
     * Calls vulnerable CVE-2022-42889 / CWE-1336 (Text4Shell RCE) in private package security-audit-logger.
     */
    public String triggerText4ShellEvaluation(String template) {
        return auditLogger.renderTemplateText4Shell(template);
    }

    /**
     * Calls vulnerable CWE-347 (Improper Signature Verification / Alg None Bypass) in private package security-token-validator.
     */
    public TokenValidationResult validateTokenWithInsecureBypass(String token) {
        SecurityTokenValidator validator = new SecurityTokenValidator();
        return validator.validateTokenInsecureSignatureBypass(token);
    }

    /**
     * Calls vulnerable CWE-208 (Timing Attack on HMAC Signature) in private package security-token-validator.
     */
    public boolean validateTokenWithTimingVulnerability(byte[] expectedSig, byte[] actualSig) {
        SecurityTokenValidator validator = new SecurityTokenValidator();
        return validator.verifySignatureWithTimingVulnerability(expectedSig, actualSig);
    }

    /**
     * Calls vulnerable CWE-327 (Weak MD5 Digest) in private package security-token-validator.
     */
    public String generateInsecureMd5Token(String subject, String secret) throws GeneralSecurityException {
        SecurityTokenValidator validator = new SecurityTokenValidator();
        return validator.generateWeakMd5Token(subject, secret);
    }

    /**
     * Calls vulnerable CWE-502 (Untrusted Object Deserialization) in private package security-token-validator.
     */
    public Object deserializeUntrustedTokenStream(byte[] payload) throws Exception {
        SecurityTokenValidator validator = new SecurityTokenValidator();
        return validator.deserializeUntrustedObjectToken(payload);
    }

    /**
     * Calls vulnerable CWE-330 (Insecure Randomness) in private package security-token-validator.
     */
    public long generateWeakNonce() {
        SecurityTokenValidator validator = new SecurityTokenValidator();
        return validator.generateInsecureRandomNonce();
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
