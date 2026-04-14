import models.Alert;
import models.LogEntry;
import models.Severity;
import detectors.SQLInjectionDetector;
import detectors.ThreatDetector;
import detectors.VulnerabilityScanDetector;
import detectors.BruteForceDetect;
import detectors.DdosDetect;
import detectors.CorreAlert;
import utils.ReportGenerator;
import utils.WhitelistManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * NetSentinel - Network Log Analyzer & Intrusion Detection System
 * 
 * Main entry point for the security analysis tool.
 * Combines log parsing, statistical analysis, threat detection, alert correlation,
 * and report generation in a unified workflow.
 * Integrates dashboard from MainMatteo, detection from Main, with batch detectors.
 */
public class Main {
    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║              NETSENTINEL - Network Log Analyzer                        ║");
        System.out.println("║                    & Intrusion Detection System                        ║");
        System.out.println("╚════════════════════════════════════════════════════════════════════════╝\n");

        // ========== SÉLECTION DU FICHIER DE LOG ==========
        String logFile = selectLogFile();
        if (logFile == null) {
            System.err.println("❌ No log file selected. Exiting.");
            return;
        }

        // Configuration
        String whitelistFile = "whitelist.txt";
        String reportFile = "rapport_securite.txt";
        String rulesFile = "regles_blocage.txt";

        // ========== ÉTAPE 1: PARSING ==========
        System.out.println("📂 Loading logs from: " + logFile);
        List<LogEntry> logs = parseLogFile(logFile);
        if (logs.isEmpty()) {
            System.err.println("❌ No logs loaded. Exiting.");
            return;
        }
        System.out.println("✓ " + logs.size() + " log entries parsed\n");

        // ========== ÉTAPE 2: DASHBOARD & STATISTIQUES ==========
        System.out.println("╔════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    NETSENTINEL - ANALYSIS DASHBOARD                   ║");
        System.out.println("╚════════════════════════════════════════════════════════════════════════╝\n");
        
        Set<String> whitelistIps = loadWhitelist(whitelistFile);
        displayDashboard(logs, whitelistIps);

        // ========== ÉTAPE 3: DÉTECTION DE MENACES ==========
        System.out.println("\n🔍 Running threat detectors...");
        List<Alert> allAlerts = new ArrayList<>();
        
        // Gestionnaire de whitelist
        WhitelistManager whitelist = new WhitelistManager(whitelistFile);

        // Détecteurs per-LogEntry
        List<ThreatDetector> detectors = new ArrayList<>();
        detectors.add(new SQLInjectionDetector());
        detectors.add(new VulnerabilityScanDetector());

        // Détection pattern-based (pour chaque entrée)
        System.out.println("  - Running pattern-based detectors...");
        for (LogEntry log : logs) {
            if (whitelist.isWhitelisted(log.getIpAddress())) {
                continue;
            }
            for (ThreatDetector detector : detectors) {
                List<Alert> alerts = detector.detect(log, logs);
                allAlerts.addAll(alerts);
            }
        }

        // Détection batch (force brute, DDoS sur l'historique complet)
        System.out.println("  - Checking for Brute Force attempts...");
        BruteForceDetect bruteForceDetector = new BruteForceDetect();
        List<Alert> bruteForceAlerts = bruteForceDetector.detect(logs);
        allAlerts.addAll(bruteForceAlerts);

        System.out.println("  - Checking for DDoS patterns...");
        DdosDetect ddosDetector = new DdosDetect();
        List<Alert> ddosAlerts = ddosDetector.detect(logs);
        allAlerts.addAll(ddosAlerts);

        System.out.println("✓ Detection completed: " + allAlerts.size() + " alerts detected\n");

        // ========== ÉTAPE 4: CORRÉLATION D'ALERTES ==========
        System.out.println("📊 Correlating alerts...");
        allAlerts = CorreAlert.correlate(allAlerts);
        System.out.println("✓ Correlation complete\n");

        // ========== ÉTAPE 5: RÉSUMÉ & RAPPORT ==========
        displayAlertsSummary(allAlerts);

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
    private static List<LogEntry> parseLogFile(String filepath) {
        List<LogEntry> logs = new ArrayList<>();
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
        return logs;
    }

    /**
     * Charge la liste blanche depuis un fichier
     */
    private static Set<String> loadWhitelist(String whitelistFile) {
        Set<String> whitelist = new HashSet<>();
        try (BufferedReader br = new BufferedReader(new FileReader(whitelistFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.trim().isEmpty() && !line.startsWith("#")) {
                    whitelist.add(line.trim());
                }
            }
            if (!whitelist.isEmpty()) {
                System.out.println("[INFO] Whitelist loaded (" + whitelist.size() + " IPs)");
            }
        } catch (IOException e) {
            System.err.println("[WARNING] No whitelist.txt found.");
        }
        return whitelist;
    }

    /**
     * Affiche le dashboard statistique (adapté de MainMatteo)
     */
    private static void displayDashboard(List<LogEntry> logs, Set<String> whitelist) {
        System.out.println("1. Total number of requests parsed: " + logs.size());

        // Top 10 des IPs (hors whitelist)
        System.out.println("\n2. Top 10 most active IPs (excluding whitelist):");
        getTopElements(logs, "IP", 10, whitelist).forEach((ip, count) ->
            System.out.println("   - " + ip + ": " + count + " requests"));

        // Distribution des codes HTTP
        System.out.println("\n3. HTTP Status Code distribution:");
        Map<Integer, Long> httpCodes = getHttpStatusDistribution(logs);
        httpCodes.forEach((code, count) ->
            System.out.println("   - Code " + code + ": " + count + " times"));

        // Top 10 des URLs
        System.out.println("\n4. Top 10 most accessed URLs:");
        getTopElements(logs, "URL", 10, null).forEach((url, count) ->
            System.out.println("   - " + url + ": " + count + " accesses"));

        // Top 5 des User-Agents
        System.out.println("\n5. Top 5 User-Agents:");
        getTopElements(logs, "UA", 5, null).forEach((ua, count) ->
            System.out.println("   - " + ua + ": " + count));

        System.out.println("\n" + "═".repeat(73) + "\n");
    }

    /**
     * Affiche les fichiers disponibles et permet à l'utilisateur de sélectionner un fichier de log
     */
    private static String selectLogFile() {
        File dataDir = new File("data");
        if (!dataDir.exists() || !dataDir.isDirectory()) {
            System.err.println("❌ Data directory not found!");
            return null;
        }

        File[] logFiles = dataDir.listFiles((dir, name) -> name.endsWith(".txt"));
        if (logFiles == null || logFiles.length == 0) {
            System.err.println("❌ No log files found in data/ directory!");
            return null;
        }

        System.out.println("📂 Available log files in data/ directory:\n");
        for (int i = 0; i < logFiles.length; i++) {
            long sizeKB = logFiles[i].length() / 1024;
            System.out.println("   [" + (i + 1) + "] " + logFiles[i].getName() + " (" + sizeKB + " KB)");
        }

        System.out.print("\n👉 Select file number (1-" + logFiles.length + "): ");
        Scanner scanner = new Scanner(System.in);
        
        int choice = -1;
        try {
            String input = scanner.nextLine().trim();
            choice = Integer.parseInt(input);
            
            if (choice < 1 || choice > logFiles.length) {
                System.err.println("❌ Invalid choice!");
                return null;
            }
        } catch (NumberFormatException e) {
            System.err.println("❌ Please enter a valid number!");
            return null;
        }

        String selectedFile = logFiles[choice - 1].getPath();
        System.out.println("\n✓ Selected: " + selectedFile + "\n");
        return selectedFile;
    }

    /**
     * Méthode polyvalente pour calculer les Tops (IP, URL, ou User-Agent)
     */
    private static Map<String, Long> getTopElements(List<LogEntry> logs, String type, int limit, Set<String> whitelist) {
        Map<String, Long> counts = new HashMap<>();

        for (LogEntry log : logs) {
            String value = "";
            switch (type) {
                case "IP":  value = log.getIpAddress(); break;
                case "URL": value = log.getUrl(); break;
                case "UA":  value = log.getUserAgent(); break;
            }

            if (type.equals("IP") && whitelist != null && whitelist.contains(value)) {
                continue;
            }

            if (value != null && !value.isEmpty()) {
                counts.put(value, counts.getOrDefault(value, 0L) + 1);
            }
        }

        return counts.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(limit)
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                Map.Entry::getValue,
                (e1, e2) -> e1,
                LinkedHashMap::new
            ));
    }

    /**
     * Distribution des codes HTTP
     */
    private static Map<Integer, Long> getHttpStatusDistribution(List<LogEntry> logs) {
        Map<Integer, Long> stats = new TreeMap<>();
        for (LogEntry log : logs) {
            int code = log.getStatusCode();
            stats.put(code, stats.getOrDefault(code, 0L) + 1);
        }
        return stats;
    }

    /**
     * Affiche un résumé des alertes détectées
     */
    private static void displayAlertsSummary(List<Alert> alerts) {
        System.out.println("═════════════════════════════════════════════════════════════════════════");
        System.out.println("ALERTS SUMMARY");
        System.out.println("═════════════════════════════════════════════════════════════════════════\n");

        if (alerts.isEmpty()) {
            System.out.println("✓ No alerts detected - System is clean!\n");
            return;
        }

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
