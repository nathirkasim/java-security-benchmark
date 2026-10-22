package com.benchmark.security.audit;

import java.time.Instant;

/**
 * Immutable security audit event representation.
 */
public class AuditEvent {
    private final String eventId;
    private final Instant timestamp;
    private final AuditSeverity severity;
    private final String principal;
    private final String action;
    private final String targetResource;
    private final boolean success;
    private final String message;

    public AuditEvent(String eventId, Instant timestamp, AuditSeverity severity,
                      String principal, String action, String targetResource,
                      boolean success, String message) {
        this.eventId = eventId;
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.severity = severity != null ? severity : AuditSeverity.INFO;
        this.principal = principal != null ? principal : "anonymous";
        this.action = action != null ? action : "UNKNOWN";
        this.targetResource = targetResource != null ? targetResource : "N/A";
        this.success = success;
        this.message = message != null ? message : "";
    }

    public String getEventId() {
        return eventId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public AuditSeverity getSeverity() {
        return severity;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getAction() {
        return action;
    }

    public String getTargetResource() {
        return targetResource;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public String toJson() {
        return String.format(
            "{\"eventId\":\"%s\",\"timestamp\":\"%s\",\"severity\":\"%s\",\"principal\":\"%s\",\"action\":\"%s\",\"resource\":\"%s\",\"success\":%b,\"message\":\"%s\"}",
            escapeJson(eventId),
            timestamp.toString(),
            severity.name(),
            escapeJson(principal),
            escapeJson(action),
            escapeJson(targetResource),
            success,
            escapeJson(message)
        );
    }

    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\b", "\\b")
                    .replace("\f", "\\f")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }

    @Override
    public String toString() {
        return String.format("[%s] [%s] principal=%s action=%s resource=%s success=%s message=%s",
                timestamp, severity, principal, action, targetResource, success, message);
    }
}
