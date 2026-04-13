package utils;

import models.Alert;
import models.Severity;
import java.io.FileWriter;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Génère le rapport de sécurité en texte et les règles de blocage
 */
public class ReportGenerator {
    private final DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Génère un rapport de sécurité
     * @param alerts liste de toutes les alertes
     * @param outputFile chemin du fichier de sortie
     */
    public void generateSecurityReport(List<Alert> alerts, String outputFile) {
        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write(generateReportContent(alerts));
            System.out.println("Rapport de sécurité généré: " + outputFile);
        } catch (IOException e) {
            System.err.println("Erreur lors de la génération du rapport: " + e.getMessage());
        }
    }

    private String generateReportContent(List<Alert> alerts) {
        StringBuilder sb = new StringBuilder();

        // En-tête
        sb.append("╔════════════════════════════════════════════════════════════════════════╗\n");
        sb.append("║                    NETSENTINEL - SECURITY REPORT                       ║\n");
        sb.append("║                  Network Log Analyzer & Intrusion Detection            ║\n");
        sb.append("╚════════════════════════════════════════════════════════════════════════╝\n\n");

        // 1. Résumé exécutif
        sb.append("═════════════════════════════════════════════════════════════════════════\n");
        sb.append("1. EXECUTIVE SUMMARY\n");
        sb.append("═════════════════════════════════════════════════════════════════════════\n\n");

        Map<Severity, Long> alertsBySeverity = alerts.stream()
            .collect(Collectors.groupingBy(Alert::getSeverity, Collectors.counting()));

        long criticalCount = alertsBySeverity.getOrDefault(Severity.CRITICAL, 0L);
        long highCount = alertsBySeverity.getOrDefault(Severity.HIGH, 0L);
        long mediumCount = alertsBySeverity.getOrDefault(Severity.MEDIUM, 0L);
        long lowCount = alertsBySeverity.getOrDefault(Severity.LOW, 0L);

        sb.append(String.format("Total Alerts: %d\n", alerts.size()));
        sb.append(String.format("  🔴 CRITICAL:  %d\n", criticalCount));
        sb.append(String.format("  🟠 HIGH:      %d\n", highCount));
        sb.append(String.format("  🟡 MEDIUM:    %d\n", mediumCount));
        sb.append(String.format("  🟢 LOW:       %d\n\n", lowCount));

        // Top IPs dangereuses
        Map<String, List<Alert>> alertsByIp = alerts.stream()
            .collect(Collectors.groupingBy(Alert::getIpAddress));

        List<Map.Entry<String, List<Alert>>> topIps = alertsByIp.entrySet().stream()
            .sorted((e1, e2) -> {
                // Trier par sévérité max d'abord, puis par nombre d'alertes
                Severity maxSev1 = e1.getValue().stream().map(Alert::getSeverity).max(Comparator.naturalOrder()).orElse(Severity.LOW);
                Severity maxSev2 = e2.getValue().stream().map(Alert::getSeverity).max(Comparator.naturalOrder()).orElse(Severity.LOW);
                if (maxSev1 != maxSev2) return maxSev2.ordinal() - maxSev1.ordinal();
                return e2.getValue().size() - e1.getValue().size();
            })
            .limit(10)
            .toList();

        sb.append("\nMost Dangerous IPs (Top 10):\n");
        sb.append("───────────────────────────────────────────────────────────────────────\n");
        for (int i = 0; i < topIps.size(); i++) {
            Map.Entry<String, List<Alert>> entry = topIps.get(i);
            Severity maxSev = entry.getValue().stream()
                .map(Alert::getSeverity)
                .max(Comparator.naturalOrder())
                .orElse(Severity.LOW);
            sb.append(String.format("%2d. %-15s | Alerts: %3d | Max Severity: %s\n",
                i + 1, entry.getKey(), entry.getValue().size(), maxSev.getDisplayName()));
        }

        // 2. Timeline chronologique
        sb.append("\n═════════════════════════════════════════════════════════════════════════\n");
        sb.append("2. INCIDENT TIMELINE (Chronological Order)\n");
        sb.append("═════════════════════════════════════════════════════════════════════════\n\n");

        List<Alert> sortedAlerts = alerts.stream()
            .sorted(Comparator.comparing(Alert::getTimestamp))
            .toList();

        for (Alert alert : sortedAlerts) {
            sb.append(String.format("[%s] %s | %s (%s) | %s\n",
                alert.getTimestamp().format(dateFormatter),
                alert.getSeverity().getDisplayName().toUpperCase(),
                alert.getThreatType(),
                alert.getIpAddress(),
                alert.getDescription()));
        }

        // 3. Détail par IP
        sb.append("\n═════════════════════════════════════════════════════════════════════════\n");
        sb.append("3. DETAILED ALERTS PER IP\n");
        sb.append("═════════════════════════════════════════════════════════════════════════\n\n");

        for (Map.Entry<String, List<Alert>> entry : alertsByIp.entrySet().stream()
                .sorted((e1, e2) -> {
                    Severity maxSev1 = e1.getValue().stream().map(Alert::getSeverity).max(Comparator.naturalOrder()).orElse(Severity.LOW);
                    Severity maxSev2 = e2.getValue().stream().map(Alert::getSeverity).max(Comparator.naturalOrder()).orElse(Severity.LOW);
                    if (maxSev1 != maxSev2) return maxSev2.ordinal() - maxSev1.ordinal();
                    return e2.getValue().size() - e1.getValue().size();
                })
                .toList()) {

            String ip = entry.getKey();
            List<Alert> ipAlerts = entry.getValue();

            Severity maxSev = ipAlerts.stream()
                .map(Alert::getSeverity)
                .max(Comparator.naturalOrder())
                .orElse(Severity.LOW);

            sb.append(String.format("\n┌─ IP: %s (Max Severity: %s, Total Alerts: %d)\n",
                ip, maxSev.getDisplayName(), ipAlerts.size()));

            Map<String, List<Alert>> byType = ipAlerts.stream()
                .collect(Collectors.groupingBy(Alert::getThreatType));

            for (Map.Entry<String, List<Alert>> typeEntry : byType.entrySet()) {
                sb.append(String.format("│  ├─ %s (%d)\n", typeEntry.getKey(), typeEntry.getValue().size()));
                for (Alert a : typeEntry.getValue()) {
                    sb.append(String.format("│  │  • [%s] %s\n",
                        a.getTimestamp().format(dateFormatter),
                        a.getDescription()));
                }
            }
            sb.append("└\n");
        }

        // 4. Recommandations
        sb.append("\n═════════════════════════════════════════════════════════════════════════\n");
        sb.append("4. RECOMMENDATIONS\n");
        sb.append("═════════════════════════════════════════════════════════════════════════\n\n");

        if (criticalCount > 0) {
            sb.append("🔴 CRITICAL Threats Detected:\n");
            sb.append("   → IMMEDIATE ACTION REQUIRED: Block these IPs at the firewall\n");
            sb.append("   → Investigate file integrity and system logs\n");
            sb.append("   → Review network traffic for data exfiltration\n\n");
        }

        if (alertsByIp.entrySet().stream()
                .anyMatch(e -> e.getValue().stream()
                    .anyMatch(a -> a.getThreatType().equals("SQL_INJECTION")))) {
            sb.append("🔏 SQL Injection Attacks:\n");
            sb.append("   → Review application input validation\n");
            sb.append("   → Use parameterized queries (prepared statements)\n");
            sb.append("   → Implement WAF rules for SQL patterns\n");
            sb.append("   → Audit database access logs\n\n");
        }

        if (alertsByIp.entrySet().stream()
                .anyMatch(e -> e.getValue().stream()
                    .anyMatch(a -> a.getThreatType().contains("SCAN")))) {
            sb.append("🔍 Vulnerability Scanning Detected:\n");
            sb.append("   → Hide sensitive paths (admin, config, .git, etc.)\n");
            sb.append("   → Implement basic authentication on admin panels\n");
            sb.append("   → Use robots.txt and rate limiting\n");
            sb.append("   → Deploy intrusion detection at IDS/IPS level\n\n");
        }

        // Pied de page
        sb.append("\n═════════════════════════════════════════════════════════════════════════\n");
        sb.append("End of Report\n");
        sb.append("═════════════════════════════════════════════════════════════════════════\n");

        return sb.toString();
    }

    /**
     * Génère les règles de blocage pour les IPs dangereuses
     * @param alerts liste de toutes les alertes
     * @param outputFile chemin du fichier de sortie
     */
    public void generateBlockingRules(List<Alert> alerts, String outputFile) {
        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write(generateBlockingRulesContent(alerts));
            System.out.println("Règles de blocage générées: " + outputFile);
        } catch (IOException e) {
            System.err.println("Erreur lors de la génération des règles: " + e.getMessage());
        }
    }

    private String generateBlockingRulesContent(List<Alert> alerts) {
        StringBuilder sb = new StringBuilder();

        sb.append("# NETSENTINEL - Blocking Rules\n");
        sb.append("# Auto-generated blocking rules for HIGH and CRITICAL IPs\n");
        sb.append("# Timestamp: ").append(java.time.LocalDateTime.now()).append("\n\n");

        Map<String, List<Alert>> alertsByIp = alerts.stream()
            .collect(Collectors.groupingBy(Alert::getIpAddress));

        // Filtrer les IPs HIGH et CRITICAL
        List<String> dangerousIps = alertsByIp.entrySet().stream()
            .filter(e -> {
                Severity maxSev = e.getValue().stream()
                    .map(Alert::getSeverity)
                    .max(Comparator.naturalOrder())
                    .orElse(Severity.LOW);
                return maxSev == Severity.HIGH || maxSev == Severity.CRITICAL;
            })
            .map(Map.Entry::getKey)
            .sorted()
            .toList();

        sb.append("# Total IPs to block: ").append(dangerousIps.size()).append("\n\n");

        // iptables rules
        sb.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        sb.append("iptables Rules (Linux Firewall)\n");
        sb.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        for (String ip : dangerousIps) {
            Severity maxSev = alertsByIp.get(ip).stream()
                .map(Alert::getSeverity)
                .max(Comparator.naturalOrder())
                .orElse(Severity.LOW);

            sb.append("# ").append(maxSev.getDisplayName()).append(" - ").append(ip).append("\n");
            sb.append(String.format("iptables -I INPUT -s %s -j DROP\n", ip));
            sb.append(String.format("iptables -I INPUT -s %s -j REJECT --reject-with icmp-host-prohibited\n\n", ip));
        }

        // .htaccess rules
        sb.append("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        sb.append(".htaccess Rules (Apache Web Server)\n");
        sb.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        sb.append("<IfModule mod_rewrite.c>\n");
        sb.append("    RewriteEngine On\n\n");

        for (String ip : dangerousIps) {
            sb.append(String.format("    # Block IP: %s\n", ip));
            sb.append(String.format("    RewriteCond %%{REMOTE_ADDR} ^%s$ [NC]\n", ip));
            sb.append("    RewriteRule ^.*$ - [F,L]\n\n");
        }

        sb.append("</IfModule>\n");

        // Nginx rules
        sb.append("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        sb.append("Nginx Rules (nginx.conf)\n");
        sb.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        sb.append("# Add this inside 'http' or 'server' block:\n\n");

        for (String ip : dangerousIps) {
            sb.append(String.format("deny %s; # %s\n", ip, alertsByIps(alertsByIp, ip)));
        }

        sb.append("\n# Summary:\n");
        for (String ip : dangerousIps) {
            Severity maxSev = alertsByIp.get(ip).stream()
                .map(Alert::getSeverity)
                .max(Comparator.naturalOrder())
                .orElse(Severity.LOW);

            List<String> threats = alertsByIp.get(ip).stream()
                .map(Alert::getThreatType)
                .distinct()
                .toList();

            sb.append(String.format("%s | %s | Threats: %s\n", ip, maxSev.getDisplayName(), String.join(", ", threats)));
        }

        return sb.toString();
    }

    private String alertsByIps(Map<String, List<Alert>> map, String ip) {
        if (!map.containsKey(ip)) return "N/A";
        return map.get(ip).stream()
            .map(Alert::getThreatType)
            .distinct()
            .limit(3)
            .collect(Collectors.joining(", "));
    }
}
