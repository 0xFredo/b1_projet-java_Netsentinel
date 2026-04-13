package detectors;

import models.Alert;
import models.LogEntry;
import models.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Détecteur d'injection SQL
 * Cherche des patterns suspects dans les URLs
 */
public class SQLInjectionDetector implements ThreatDetector {

    // Patterns d'injection SQL courants (case-insensitive)
    private static final List<Pattern> SQL_PATTERNS = List.of(
        Pattern.compile("('|%27)\\s*(OR|AND)\\s*('|%27|\\d)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(OR|AND)\\s*1\\s*=\\s*1", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(OR|AND)\\s*'.*'\\s*=\\s*'.*'", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\\s+(.*)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("--|;|\\*|\\\\", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(xp_|sp_|exec|execute|script|javascript)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(SLEEP|BENCHMARK|WAITFOR)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(%00|\\x00|char\\(|ascii\\(|substring)", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public List<Alert> detect(LogEntry entry, List<LogEntry> historique) {
        List<Alert> alerts = new ArrayList<>();

        if (entry == null || entry.getUrl() == null) {
            return alerts;
        }

        String url = entry.getUrl();
        String decodedUrl = decodeUrl(url);

        for (Pattern pattern : SQL_PATTERNS) {
            if (pattern.matcher(decodedUrl).find()) {
                String description = String.format("SQL injection pattern detected in URL: %s", url);
                Alert alert = new Alert(
                    entry.getIpAddress(),
                    Severity.HIGH,
                    "SQL_INJECTION",
                    description,
                    entry.getTimestamp(),
                    entry
                );
                alerts.add(alert);
                break; // Une seule alerte par entry pour éviter les doublons
            }
        }

        return alerts;
    }

    /**
     * Décode les URL encodées basiques (%XX)
     */
    private String decodeUrl(String url) {
        return url.replace("%27", "'")
                  .replace("%20", " ")
                  .replace("%2F", "/")
                  .replace("%3D", "=")
                  .replace("%2B", "+")
                  .replace("%00", "");
    }

    @Override
    public String getName() {
        return "SQL Injection Detector";
    }
}
