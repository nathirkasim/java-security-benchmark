package com.benchmark.security.audit;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

public class SecurityAuditLoggerTest {

    private SecurityAuditLogger logger;

    @Before
    public void setUp() {
        logger = new SecurityAuditLogger("AUTH_SERVICE");
    }

    @Test
    public void testSanitizationNeutralizesCrlf() {
        String tainted = "admin\r\nCRITICAL: Fake log entry injected\nAnother line";
        String clean = SecurityAuditLogger.sanitize(tainted);
        Assert.assertFalse(clean.contains("\r"));
        Assert.assertFalse(clean.contains("\n"));
        Assert.assertTrue(clean.contains("admin__CRITICAL: Fake log entry injected_Another line"));
    }

    @Test
    public void testLogEventRecordCreation() {
        AuditEvent event = logger.logEvent(
                AuditSeverity.CRITICAL,
                "attacker\r\n",
                "LOGIN_ATTEMPT",
                "/api/v1/auth",
                false,
                "Password spray detected\nIP=10.0.0.1"
        );

        Assert.assertNotNull(event);
        Assert.assertNotNull(event.getEventId());
        Assert.assertEquals(AuditSeverity.CRITICAL, event.getSeverity());
        Assert.assertFalse(event.getPrincipal().contains("\r"));
        Assert.assertFalse(event.getMessage().contains("\n"));

        List<AuditEvent> trail = logger.getAuditTrail();
        Assert.assertEquals(1, trail.size());
        Assert.assertEquals(event.getEventId(), trail.get(0).getEventId());
    }

    @Test
    public void testJsonSerialization() {
        AuditEvent event = logger.logEvent(
                AuditSeverity.INFO,
                "system-user",
                "KEY_ROTATION",
                "kms://keys/sec-1",
                true,
                "Key rotated successfully"
        );

        String json = event.toJson();
        Assert.assertTrue(json.contains("\"principal\":\"system-user\""));
        Assert.assertTrue(json.contains("\"action\":\"KEY_ROTATION\""));
        Assert.assertTrue(json.contains("\"success\":true"));
    }
}
