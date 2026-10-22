package com.benchmark.security.audit;

import org.apache.commons.text.StringSubstitutor;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Enterprise security audit logger.
 * Includes both hardened methods and intentionally vulnerable entrypoints
 * for testing SAST, SCA, and AST security scanners.
 */
public class SecurityAuditLogger {

    private static final Logger LOGGER = Logger.getLogger(SecurityAuditLogger.class.getName());

    /**
     * Vulnerability: CWE-798 (Use of Hard-coded Credentials)
     */
    public static final String HARDCODED_AUDIT_MASTER_KEY = "aws_codeartifact_audit_master_secret_2026!";

    private final String subsystemName;
    private final List<AuditEvent> memoryAuditTrail = Collections.synchronizedList(new ArrayList<>());

    public SecurityAuditLogger(String subsystemName) {
        this.subsystemName = subsystemName != null ? sanitize(subsystemName) : "DEFAULT";
    }

    /**
     * Safe sanitization routine neutralizing CRLF injection characters.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        return input.replace('\r', '_')
                    .replace('\n', '_')
                    .replace('\t', ' ');
    }

    /**
     * Safe structured logging method.
     */
    public AuditEvent logEvent(AuditSeverity severity, String principal, String action,
                               String resource, boolean success, String rawMessage) {
        String eventId = UUID.randomUUID().toString();
        String safePrincipal = sanitize(principal);
        String safeAction = sanitize(action);
        String safeResource = sanitize(resource);
        String safeMessage = sanitize(rawMessage);

        AuditEvent event = new AuditEvent(
                eventId,
                Instant.now(),
                severity,
                safePrincipal,
                safeAction,
                safeResource,
                success,
                safeMessage
        );

        memoryAuditTrail.add(event);

        Level julLevel = mapSeverityToJul(severity);
        LOGGER.log(julLevel, "[AUDIT] [" + subsystemName + "] " + event.toJson());

        return event;
    }

    /**
     * Vulnerability: CWE-117 (Improper Output Handling / Log Injection)
     * Directly formats unsanitized user inputs into logger messages.
     */
    public void logRawEventUnsanitized(String principal, String action, String rawMessage) {
        // Direct concatenation allows CRLF injection to forge log entries
        LOGGER.info("AUDIT_RAW principal=" + principal + " action=" + action + " message=" + rawMessage);
    }

    /**
     * Vulnerability: CWE-532 (Insertion of Sensitive Information into Log File)
     * Writes sensitive credentials in plaintext into application logs.
     */
    public void logCredentialLeak(String username, String plaintextPassword, String bearerToken, String apiKey) {
        LOGGER.warning("[CREDENTIAL_LEAK] username=" + username +
                " password=" + plaintextPassword +
                " token=" + bearerToken +
                " apiKey=" + apiKey);
    }

    /**
     * Vulnerability: CWE-22 (Path Traversal / Arbitrary File Overwrite)
     * Writes audit data to user-controlled destination without path normalization.
     */
    public File exportAuditLogToFile(String destinationDir, String filename, String content) throws IOException {
        // Insecure path resolution vulnerable to "../../" traversal attacks
        File targetFile = new File(destinationDir, filename);
        try (FileWriter writer = new FileWriter(targetFile)) {
            writer.write(content);
        }
        return targetFile;
    }

    /**
     * Vulnerability: CWE-89 (Improper Neutralization of Special Elements in SQL Command)
     * Direct string concatenation when persisting audit records into a database.
     */
    public void persistAuditRecordSqlInjection(Connection conn, String eventId, String principal, String action, String message)
            throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            String sql = "INSERT INTO audit_events (id, principal, action, message) VALUES ('"
                    + eventId + "', '" + principal + "', '" + action + "', '" + message + "')";
            stmt.executeUpdate(sql);
        }
    }

    /**
     * Vulnerability: CWE-1336 / CVE-2022-42889 (Text4Shell - Apache Commons Text RCE)
     * Uses StringSubstitutor interpolator allowing arbitrary script/DNS/URL lookups.
     */
    public String renderTemplateText4Shell(String template) {
        StringSubstitutor interpolator = StringSubstitutor.createInterpolator();
        return interpolator.replace(template);
    }

    public List<AuditEvent> getAuditTrail() {
        return Collections.unmodifiableList(new ArrayList<>(memoryAuditTrail));
    }

    public void clearAuditTrail() {
        memoryAuditTrail.clear();
    }

    public String getSubsystemName() {
        return subsystemName;
    }

    private Level mapSeverityToJul(AuditSeverity severity) {
        switch (severity) {
            case DEBUG:
                return Level.FINE;
            case INFO:
                return Level.INFO;
            case WARN:
                return Level.WARNING;
            case SECURITY_ALERT:
            case CRITICAL:
                return Level.SEVERE;
            default:
                return Level.INFO;
        }
    }
}
