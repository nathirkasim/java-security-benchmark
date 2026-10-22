package com.benchmark.security.audit;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Enterprise security audit logger.
 * Sanitizes input to prevent CRLF log injection (CWE-117) and records structured audit events.
 */
public class SecurityAuditLogger {

    private static final Logger LOGGER = Logger.getLogger(SecurityAuditLogger.class.getName());
    private final String subsystemName;
    private final List<AuditEvent> memoryAuditTrail = Collections.synchronizedList(new ArrayList<>());

    public SecurityAuditLogger(String subsystemName) {
        this.subsystemName = subsystemName != null ? sanitize(subsystemName) : "DEFAULT";
    }

    /**
     * Sanitizes inputs to neutralize CRLF characters and prevent log injection vulnerabilities.
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
     * Records an audit event with automatic sanitization and UUID generation.
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
