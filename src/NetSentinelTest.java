import models.LogEntry;
import models.Alert;
import models.Severity;
import detectors.SQLInjectionDetector;
import detectors.VulnerabilityScanDetector;
import utils.WhitelistManager;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * NetSentinel Security Detectors Tests
 * Custom test suite without JUnit dependencies
 */
public class NetSentinelTest {

    private static int testsPassed = 0;
    private static int testsFailed = 0;

    // Custom Assertion Methods
    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            fail(message);
        }
    }

    private static void assertFalse(boolean condition, String message) {
        if (condition) {
            fail(message);
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (!expected.equals(actual)) {
            fail("Expected: " + expected + ", but got: " + actual);
        }
    }

    private static void assertNull(Object obj, String message) {
        if (obj != null) {
            fail(message);
        }
    }

    private static void assertNotNull(Object obj, String message) {
        if (obj == null) {
            fail(message);
        }
    }

    private static void assertNotNull(Object obj) {
        if (obj == null) {
            fail("Object should not be null");
        }
    }

    private static void pass(String testName) {
        testsPassed++;
        System.out.println("✓ PASS: " + testName);
    }

    private static void fail(String message) {
        testsFailed++;
        System.out.println("✗ FAIL: " + message);
        throw new AssertionError(message);
    }

    /**
     * Main entry point - runs all tests
     */
    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║           NETSENTINEL SECURITY DETECTORS TEST SUITE                   ║");
        System.out.println("╚════════════════════════════════════════════════════════════════════════╝\n");

        try {
            testLogParsing();
            testLogParsingInvalid();
            testSQLInjectionDetection();
            testNormalRequestNoSQLAlert();
            testSQLInjectionUnionSelect();
            testSuspiciousUserAgentDetection();
            testSuspiciousPathDetection();
            testAdminPanelDetection();
            testWhitelistAddition();
            testNonWhitelistedIP();
            testAlertCreation();
            testSeverityElevation();
            testMultipleDetectorsTrigger();
            testNullInputs();
            testURLDecoding();
        } catch (Exception e) {
            System.err.println("\n⚠️ Test execution interrupted: " + e.getMessage());
        }

        printSummary();
    }

    private static void printSummary() {
        System.out.println("\n╔════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                          TEST SUMMARY                                  ║");
        System.out.println("╚════════════════════════════════════════════════════════════════════════╝");
        System.out.println("Tests Passed: ✓ " + testsPassed);
        System.out.println("Tests Failed: ✗ " + testsFailed);
        System.out.println("Total Tests:  " + (testsPassed + testsFailed));
        System.out.println("═".repeat(73) + "\n");
        
        if (testsFailed == 0) {
            System.out.println("✅ All tests passed!");
        } else {
            System.out.println("❌ Some tests failed!");
        }
    }

    // ======================== TEST 1: Log Parsing ========================
    static void testLogParsing() {
        String logLine = "192.168.1.45 - - [15/Mar/2025:10:23:45 +0100] \"GET /index.html HTTP/1.1\" 200 5423 \"-\" \"Mozilla/5.0\"";
        
        LogEntry entry = LogEntry.parse(logLine);
        
        try {
            assertNotNull(entry, "LogEntry should not be null");
            assertEquals("192.168.1.45", entry.getIpAddress());
            assertEquals("GET", entry.getMethod());
            assertEquals("/index.html", entry.getUrl());
            assertEquals(200, entry.getStatusCode());
            assertEquals("Mozilla/5.0", entry.getUserAgent());
            assertEquals(5423L, entry.getResponseSize());
            pass("Test 1: Correct parsing of an Apache Combined Log line");
        } catch (Exception e) {
            System.err.println("✗ Test 1 failed: " + e.getMessage());
        }
    }

    static void testLogParsingInvalid() {
        String invalidLine = "This is not a valid log line";
        LogEntry entry = LogEntry.parse(invalidLine);
        
        try {
            assertNull(entry, "LogEntry should be null for invalid log");
            pass("Test 1b: Parsing fails gracefully on invalid log line");
        } catch (Exception e) {
            System.err.println("✗ Test 1b failed: " + e.getMessage());
        }
    }

    // ======================== TEST 2: SQL Injection Detection ========================
    static void testSQLInjectionDetection() {
        String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /search?q=' OR 1=1-- HTTP/1.1\" 200 0 \"-\" \"sqlmap/1.5\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        try {
            assertNotNull(entry);
            
            SQLInjectionDetector detector = new SQLInjectionDetector();
            List<Alert> alerts = detector.detect(entry, new ArrayList<>());
            
            assertFalse(alerts.isEmpty(), "SQL injection should be detected");
            Alert alert = alerts.get(0);
            assertEquals("SQL_INJECTION", alert.getThreatType());
            assertEquals(Severity.HIGH, alert.getSeverity());
            assertEquals("203.0.113.50", alert.getIpAddress());
            pass("Test 2: SQL injection with ' OR 1=1 pattern is detected");
        } catch (Exception e) {
            System.err.println("✗ Test 2 failed: " + e.getMessage());
        }
    }

    static void testNormalRequestNoSQLAlert() {
        String logLine = "192.168.1.45 - - [15/Mar/2025:10:23:45 +0100] \"GET /index.html HTTP/1.1\" 200 5423 \"-\" \"Mozilla/5.0\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        try {
            SQLInjectionDetector detector = new SQLInjectionDetector();
            List<Alert> alerts = detector.detect(entry, new ArrayList<>());
            
            assertTrue(alerts.isEmpty(), "Normal request should not trigger alert");
            pass("Test 2b: Normal GET request does not trigger SQL injection alert");
        } catch (Exception e) {
            System.err.println("✗ Test 2b failed: " + e.getMessage());
        }
    }

    static void testSQLInjectionUnionSelect() {
        String logLine = "10.0.0.5 - - [15/Mar/2025:10:25:00 +0100] \"GET /admin?id=1 UNION SELECT * FROM users HTTP/1.1\" 200 100 \"-\" \"curl/7.68\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        try {
            SQLInjectionDetector detector = new SQLInjectionDetector();
            List<Alert> alerts = detector.detect(entry, new ArrayList<>());
            
            assertFalse(alerts.isEmpty(), "UNION SELECT injection should be detected");
            assertEquals("SQL_INJECTION", alerts.get(0).getThreatType());
            pass("Test 2c: SQL injection with UNION SELECT is detected");
        } catch (Exception e) {
            System.err.println("✗ Test 2c failed: " + e.getMessage());
        }
    }

    // ======================== TEST 3: Vulnerability Scan Detection ========================
    static void testSuspiciousUserAgentDetection() {
        String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /index.html HTTP/1.1\" 200 0 \"-\" \"sqlmap/1.5\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        try {
            VulnerabilityScanDetector detector = new VulnerabilityScanDetector();
            List<Alert> alerts = detector.detect(entry, new ArrayList<>());
            
            assertFalse(alerts.isEmpty(), "Suspicious user-agent should be detected");
            Alert alert = alerts.get(0);
            assertEquals("VULNERABILITY_SCAN_USER_AGENT", alert.getThreatType());
            pass("Test 3: Suspicious user-agent (sqlmap) is detected");
        } catch (Exception e) {
            System.err.println("✗ Test 3 failed: " + e.getMessage());
        }
    }

    static void testSuspiciousPathDetection() {
        String logLine = "10.0.0.20 - - [15/Mar/2025:10:30:00 +0100] \"GET /.env HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        try {
            VulnerabilityScanDetector detector = new VulnerabilityScanDetector();
            List<Alert> alerts = detector.detect(entry, new ArrayList<>());
            
            assertFalse(alerts.isEmpty(), "Suspicious path should be detected");
            assertEquals("VULNERABILITY_SCAN_PATH", alerts.get(0).getThreatType());
            pass("Test 3b: Suspicious path (.env) access is detected");
        } catch (Exception e) {
            System.err.println("✗ Test 3b failed: " + e.getMessage());
        }
    }

    static void testAdminPanelDetection() {
        String logLine = "10.0.0.15 - - [15/Mar/2025:10:35:00 +0100] \"GET /admin/login.php HTTP/1.1\" 403 0 \"-\" \"Mozilla/5.0\"";
        LogEntry entry = LogEntry.parse(logLine);
        
        try {
            VulnerabilityScanDetector detector = new VulnerabilityScanDetector();
            List<Alert> alerts = detector.detect(entry, new ArrayList<>());
            
            assertFalse(alerts.isEmpty(), "Admin panel access should be detected");
            assertEquals("VULNERABILITY_SCAN_PATH", alerts.get(0).getThreatType());
            pass("Test 3c: Admin panel access attempt is flagged");
        } catch (Exception e) {
            System.err.println("✗ Test 3c failed: " + e.getMessage());
        }
    }

    // ======================== TEST 4: Whitelist Functionality ========================
    static void testWhitelistAddition() {
        try {
            WhitelistManager whitelist = new WhitelistManager("test_whitelist.txt");
            String ipAddress = "192.168.1.100";
            whitelist.addToWhitelist(ipAddress);
            
            assertTrue(whitelist.isWhitelisted(ipAddress), "IP should be whitelisted");
            pass("Test 4: Whitelisted IP can be added and checked");
        } catch (Exception e) {
            System.err.println("✗ Test 4 failed: " + e.getMessage());
        }
    }

    static void testNonWhitelistedIP() {
        try {
            WhitelistManager whitelist = new WhitelistManager("test_whitelist.txt");
            String ipAddress = "203.0.113.50";
            
            assertFalse(whitelist.isWhitelisted(ipAddress), "IP should not be whitelisted");
            pass("Test 4b: Non-whitelisted IP is rejected");
        } catch (Exception e) {
            System.err.println("✗ Test 4b failed: " + e.getMessage());
        }
    }

    // ======================== TEST 5: Alert Creation ========================
    static void testAlertCreation() {
        try {
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
            pass("Test 5: Alert is created with correct properties");
        } catch (Exception e) {
            System.err.println("✗ Test 5 failed: " + e.getMessage());
        }
    }

    // ======================== TEST 6: Severity Elevation ========================
    static void testSeverityElevation() {
        try {
            Severity low = Severity.LOW;
            Severity medium = low.elevate();
            Severity high = medium.elevate();
            Severity critical = high.elevate();
            
            assertEquals(Severity.MEDIUM, medium);
            assertEquals(Severity.HIGH, high);
            assertEquals(Severity.CRITICAL, critical);
            assertEquals(Severity.CRITICAL, critical.elevate());
            pass("Test 6: Severity can be elevated correctly");
        } catch (Exception e) {
            System.err.println("✗ Test 6 failed: " + e.getMessage());
        }
    }

    // ======================== TEST 7: Multiple Detectors ========================
    static void testMultipleDetectorsTrigger() {
        try {
            String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /search?q=' OR 1=1-- HTTP/1.1\" 200 0 \"-\" \"sqlmap/1.5\"";
            LogEntry entry = LogEntry.parse(logLine);
            
            SQLInjectionDetector sqlDetector = new SQLInjectionDetector();
            VulnerabilityScanDetector scanDetector = new VulnerabilityScanDetector();
            
            List<Alert> sqlAlerts = sqlDetector.detect(entry, new ArrayList<>());
            List<Alert> scanAlerts = scanDetector.detect(entry, new ArrayList<>());
            
            assertTrue(!sqlAlerts.isEmpty() && !scanAlerts.isEmpty(), 
                "Both SQL and scan detectors should trigger");
            pass("Test 7: Single entry can trigger multiple detectors");
        } catch (Exception e) {
            System.err.println("✗ Test 7 failed: " + e.getMessage());
        }
    }

    // ======================== TEST 8: Edge Cases ========================
    static void testNullInputs() {
        try {
            SQLInjectionDetector sqlDetector = new SQLInjectionDetector();
            VulnerabilityScanDetector scanDetector = new VulnerabilityScanDetector();
            
            LogEntry nullEntry = null;
            
            List<Alert> alerts1 = sqlDetector.detect(nullEntry, new ArrayList<>());
            assertTrue(alerts1.isEmpty(), "Should not crash on null entry");
            
            List<Alert> alerts2 = scanDetector.detect(nullEntry, new ArrayList<>());
            assertTrue(alerts2.isEmpty(), "Should not crash on null entry");
            pass("Test 8: Null or empty inputs are handled gracefully");
        } catch (Exception e) {
            System.err.println("✗ Test 8 failed: " + e.getMessage());
        }
    }

    static void testURLDecoding() {
        try {
            String logLine = "203.0.113.50 - - [15/Mar/2025:10:24:15 +0100] \"GET /search?q=%27%20OR%201=1 HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"";
            LogEntry entry = LogEntry.parse(logLine);
            
            SQLInjectionDetector detector = new SQLInjectionDetector();
            List<Alert> alerts = detector.detect(entry, new ArrayList<>());
            assertFalse(alerts.isEmpty(), "Should detect encoded SQL injection");
            pass("Test 8b: URL encoding is decoded correctly");
        } catch (Exception e) {
            System.err.println("✗ Test 8b failed: " + e.getMessage());
        }
    }
}
