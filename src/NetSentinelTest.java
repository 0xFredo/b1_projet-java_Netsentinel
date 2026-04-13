import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import models.LogEntry;
import models.Alert;
import models.Severity;
import detectors.SQLInjectionDetector;
import detectors.VulnerabilityScanDetector;
import utils.WhitelistManager;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("NetSentinel Security Detectors Tests")
public class NetSentinelTest {

    private SQLInjectionDetector sqlDetector;
    private VulnerabilityScanDetector scanDetector;
    private WhitelistManager whitelist;

    @BeforeEach
    void setUp() {
        sqlDetector = new SQLInjectionDetector();
        scanDetector = new VulnerabilityScanDetector();
        whitelist = new WhitelistManager("test_whitelist.txt");
    }

    // ======================== TEST 1: Log Parsing ========================
    @Test
    @DisplayName("Test 1: Correct parsing of an Apache Combined Log line")
    void testLogParsing() {
        String logLine = "192.168.1.45 - - [15/Mar/2025:10:23:45 +0100] \"GET /index.html HTTP/1.1\" 200 5423 \"-\" \"Mozilla/5.0\"";
        
        LogEntry entry = LogEntry.parse(logLine);
        
        assertNotNull(entry, "LogEntry should not be null");
        assertEquals("192.168.1.45", entry.getIpAddress());
        assertEquals("GET", entry.getMethod());
        assertEquals("/index.html", entry.getUrl());
        assertEquals(200, entry.getStatusCode());
        assertEquals("Mozilla/5.0", entry.getUserAgent());
        assertEquals(5423, entry.getResponseSize());
    }

    @Test
    @DisplayName("Test 1b: Parsing fails gracefully on invalid log line")
    void testLogParsingInvalid() {
        String invalidLine = "This is not a valid log line";
        LogEntry entry = LogEntry.parse(invalidLine);
        assertNull(entry, "LogEntry should be null for invalid log");
    }

    // ======================== TEST 2: SQL Injection Detection ========================
    @Test
    @DisplayName("Test 2: SQL injection with ' OR 1=1 pattern is detected")
    void testSQLInjectionDetection() {
        String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /search?q=' OR 1=1-- HTTP/1.1\" 200 0 \"-\" \"sqlmap/1.5\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        assertNotNull(entry);
        
        List<Alert> alerts = sqlDetector.detect(entry, new ArrayList<>());
        
        assertFalse(alerts.isEmpty(), "SQL injection should be detected");
        Alert alert = alerts.get(0);
        assertEquals("SQL_INJECTION", alert.getThreatType());
        assertEquals(Severity.HIGH, alert.getSeverity());
        assertEquals("203.0.113.50", alert.getIpAddress());
    }

    @Test
    @DisplayName("Test 2b: Normal GET request does not trigger SQL injection alert")
    void testNormalRequestNoSQLAlert() {
        String logLine = "192.168.1.45 - - [15/Mar/2025:10:23:45 +0100] \"GET /index.html HTTP/1.1\" 200 5423 \"-\" \"Mozilla/5.0\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        List<Alert> alerts = sqlDetector.detect(entry, new ArrayList<>());
        
        assertTrue(alerts.isEmpty(), "Normal request should not trigger alert");
    }

    @Test
    @DisplayName("Test 2c: SQL injection with UNION SELECT is detected")
    void testSQLInjectionUnionSelect() {
        String logLine = "10.0.0.5 - - [15/Mar/2025:10:25:00 +0100] \"GET /admin?id=1 UNION SELECT * FROM users HTTP/1.1\" 200 100 \"-\" \"curl/7.68\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        List<Alert> alerts = sqlDetector.detect(entry, new ArrayList<>());
        
        assertFalse(alerts.isEmpty(), "UNION SELECT injection should be detected");
        assertEquals("SQL_INJECTION", alerts.get(0).getThreatType());
    }

    // ======================== TEST 3: Vulnerability Scan Detection ========================
    @Test
    @DisplayName("Test 3: Suspicious user-agent (sqlmap) is detected")
    void testSuspiciousUserAgentDetection() {
        String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /index.html HTTP/1.1\" 200 0 \"-\" \"sqlmap/1.5\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        List<Alert> alerts = scanDetector.detect(entry, new ArrayList<>());
        
        assertFalse(alerts.isEmpty(), "Suspicious user-agent should be detected");
        Alert alert = alerts.get(0);
        assertEquals("VULNERABILITY_SCAN_USER_AGENT", alert.getThreatType());
    }

    @Test
    @DisplayName("Test 3b: Suspicious path (.env) access is detected")
    void testSuspiciousPathDetection() {
        String logLine = "10.0.0.20 - - [15/Mar/2025:10:30:00 +0100] \"GET /.env HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        List<Alert> alerts = scanDetector.detect(entry, new ArrayList<>());
        
        assertFalse(alerts.isEmpty(), "Suspicious path should be detected");
        assertEquals("VULNERABILITY_SCAN_PATH", alerts.get(0).getThreatType());
    }

    @Test
    @DisplayName("Test 3c: Admin panel access attempt is flagged")
    void testAdminPanelDetection() {
        String logLine = "10.0.0.15 - - [15/Mar/2025:10:35:00 +0100] \"GET /admin/login.php HTTP/1.1\" 403 0 \"-\" \"Mozilla/5.0\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        List<Alert> alerts = scanDetector.detect(entry, new ArrayList<>());
        
        assertFalse(alerts.isEmpty(), "Admin panel access should be detected");
        assertEquals("VULNERABILITY_SCAN_PATH", alerts.get(0).getThreatType());
    }

    // ======================== TEST 4: Whitelist Functionality ========================
    @Test
    @DisplayName("Test 4: Whitelisted IP can be added and checked")
    void testWhitelistAddition() {
        String ipAddress = "192.168.1.100";
        whitelist.addToWhitelist(ipAddress);
        
        assertTrue(whitelist.isWhitelisted(ipAddress), "IP should be whitelisted");
    }

    @Test
    @DisplayName("Test 4b: Non-whitelisted IP is rejected")
    void testNonWhitelistedIP() {
        String ipAddress = "203.0.113.50";
        
        assertFalse(whitelist.isWhitelisted(ipAddress), "IP should not be whitelisted");
    }

    // ======================== TEST 5: Alert Creation ========================
    @Test
    @DisplayName("Test 5: Alert is created with correct properties")
    void testAlertCreation() {
        LocalDateTime now = LocalDateTime.now();
        String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /search?q=' OR 1=1 HTTP/1.1\" 200 0 \"-\" \"sqlmap/1.5\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        Alert alert = new Alert(
            "203.0.113.50",
            Severity.HIGH,
            "SQL_INJECTION",
            "Test description",
            now,
            entry
        );
        
        assertEquals("203.0.113.50", alert.getIpAddress());
        assertEquals(Severity.HIGH, alert.getSeverity());
        assertEquals("SQL_INJECTION", alert.getThreatType());
        assertEquals("Test description", alert.getDescription());
        assertEquals(entry, alert.getTriggeringEntry());
    }

    // ======================== TEST 6: Severity Elevation ========================
    @Test
    @DisplayName("Test 6: Severity can be elevated correctly")
    void testSeverityElevation() {
        Severity low = Severity.LOW;
        Severity medium = low.elevate();
        Severity high = medium.elevate();
        Severity critical = high.elevate();
        
        assertEquals(Severity.MEDIUM, medium);
        assertEquals(Severity.HIGH, high);
        assertEquals(Severity.CRITICAL, critical);
        // CRITICAL should stay CRITICAL
        assertEquals(Severity.CRITICAL, critical.elevate());
    }

    // ======================== TEST 7: Multiple Detectors ========================
    @Test
    @DisplayName("Test 7: Single entry can trigger multiple detectors")
    void testMultipleDetectorsTrigger() {
        // Log with both SQL injection AND suspicious user-agent
        String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /search?q=' OR 1=1-- HTTP/1.1\" 200 0 \"-\" \"sqlmap/1.5\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        List<Alert> sqlAlerts = sqlDetector.detect(entry, new ArrayList<>());
        List<Alert> scanAlerts = scanDetector.detect(entry, new ArrayList<>());
        
        assertTrue(!sqlAlerts.isEmpty() && !scanAlerts.isEmpty(), 
            "Both SQL and scan detectors should trigger");
    }

    // ======================== TEST 8: Edge Cases ========================
    @Test
    @DisplayName("Test 8: Null or empty inputs are handled gracefully")
    void testNullInputs() {
        // Test with null log entry
        LogEntry nullEntry = null;
        
        // SQL detector should handle null gracefully
        List<Alert> alerts1 = sqlDetector.detect(nullEntry, new ArrayList<>());
        assertTrue(alerts1.isEmpty(), "Should not crash on null entry");
        
        // Scan detector should handle null gracefully
        List<Alert> alerts2 = scanDetector.detect(nullEntry, new ArrayList<>());
        assertTrue(alerts2.isEmpty(), "Should not crash on null entry");
    }

    @Test
    @DisplayName("Test 8b: URL encoding is decoded correctly")
    void testURLDecoding() {
        // %27 is encoded single quote
        String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /search?q=%27%20OR%201=1 HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        List<Alert> alerts = sqlDetector.detect(entry, new ArrayList<>());
        // Should detect the encoded SQL injection
        assertFalse(alerts.isEmpty(), "Should detect encoded SQL injection");
    }
}
