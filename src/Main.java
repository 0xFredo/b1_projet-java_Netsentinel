import models.Alert;
import models.LogEntry;
import models.Severity;
import detectors.SQLInjectionDetector;
import detectors.ThreatDetector;
import detectors.VulnerabilityScanDetector;
import utils.ReportGenerator;
import utils.WhitelistManager;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * NetSentinel - Network Log Analyzer & Intrusion Detection System
 *
 * Main entry point for the security analysis tool.
 * Parses Apache access logs and detects malicious activities.
 */
public class Main {
    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║              NETSENTINEL - Network Log Analyzer                        ║");
        System.out.println("║                    & Intrusion Detection System                        ║");
        System.out.println("╚════════════════════════════════════════════════════════════════════════╝\n");

        // Configuration
        String logFile = "data/access_log_clean.txt"; // À remplacer par access_log_attack.txt pour tester
        String whitelistFile = "whitelist.txt";
        String reportFile = "rapport_securite.txt";
        String rulesFile = "regles_blocage.txt";

        // Initialiser les détecteurs
        List<ThreatDetector> detectors = new ArrayList<>();
        detectors.add(new SQLInjectionDetector());
        detectors.add(new VulnerabilityScanDetector());

        // Gestionnaire de whitelist
        WhitelistManager whitelist = new WhitelistManager(whitelistFile);

        // Parseage et détection
        List<LogEntry> logs = new ArrayList<>();
        List<Alert> allAlerts = new ArrayList<>();

        System.out.println("📂 Parsing logs from: " + logFile);
        parseLogFile(logFile, logs);
        System.out.println("✓ " + logs.size() + " log entries parsed\n");

        System.out.println("🔍 Running threat detectors...");
        for (LogEntry log : logs) {
            // Skip whitelisted IPs
            if (whitelist.isWhitelisted(log.getIpAddress())) {
                continue;
            }

            // Run all detectors
            for (ThreatDetector detector : detectors) {
                List<Alert> alerts = detector.detect(log, logs);
                allAlerts.addAll(alerts);
            }
        }
        System.out.println("✓ Detection completed: " + allAlerts.size() + " alerts detected\n");

        // Afficher un résumé en console
        displayAlertsSummary(allAlerts);

        // Générer le rapport de sécurité
        System.out.println("📝 Generating security report...");
        ReportGenerator generator = new ReportGenerator();
        generator.generateSecurityReport(allAlerts, reportFile);
        generator.generateBlockingRules(allAlerts, rulesFile);

        System.out.println("\n✅ NetSentinel analysis complete!");
        System.out.println("   - Report: " + reportFile);
        System.out.println("   - Rules: " + rulesFile);
    }

    /**
     * Parse un fichier de logs Apache Combined Format
     */
    private static void parseLogFile(String filepath, List<LogEntry> logs) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filepath))) {
            String line;
            int lineNumber = 0;
            int parseErrors = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                LogEntry entry = LogEntry.parse(line);
                if (entry != null) {
                    logs.add(entry);
                } else {
                    parseErrors++;
                }
            }

            if (parseErrors > 0) {
                System.err.println("⚠️  " + parseErrors + " lines failed to parse (total: " + lineNumber + ")");
            }
        } catch (IOException e) {
            System.err.println("❌ Error reading log file: " + e.getMessage());
        }
    }

    /**
     * Affiche un résumé des alertes détectées
     */
    private static void displayAlertsSummary(List<Alert> alerts) {
        System.out.println("═════════════════════════════════════════════════════════════════════════");
        System.out.println("ALERTS SUMMARY");
        System.out.println("═════════════════════════════════════════════════════════════════════════\n");

        Map<Severity, Integer> severityCounts = new HashMap<>();
        for (Severity s : Severity.values()) {
            severityCounts.put(s, 0);
        }

        for (Alert alert : alerts) {
            severityCounts.put(alert.getSeverity(), severityCounts.get(alert.getSeverity()) + 1);
        }

        System.out.println("Alerts by Severity:");
        System.out.println("  🔴 CRITICAL:  " + severityCounts.get(Severity.CRITICAL));
        System.out.println("  🟠 HIGH:      " + severityCounts.get(Severity.HIGH));
        System.out.println("  🟡 MEDIUM:    " + severityCounts.get(Severity.MEDIUM));
        System.out.println("  🟢 LOW:       " + severityCounts.get(Severity.LOW));

        // Top 5 des IPs dangereuses
        Map<String, Integer> ipCounts = new HashMap<>();
        for (Alert alert : alerts) {
            ipCounts.put(alert.getIpAddress(), ipCounts.getOrDefault(alert.getIpAddress(), 0) + 1);
        }

        System.out.println("\nTop 5 Dangerous IPs:");
        ipCounts.entrySet().stream()
            .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
            .limit(5)
            .forEach(e -> System.out.println("  • " + e.getKey() + ": " + e.getValue() + " alerts"));

        System.out.println("═════════════════════════════════════════════════════════════════════════\n");
    }
}
