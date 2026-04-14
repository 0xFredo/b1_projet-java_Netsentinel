package detectors;

import java.util.*;
import java.time.Duration;
import models.Alert;
import models.LogEntry;
import models.Severity;

/**
 * Détecteur de tentatives de brute-force
 * Analyse les logs pour détecter des patterns de connexions échouées répétées
 */
public class BruteForceDetect {
    private static final int WINDOW_MINUTES = 5;

    /**
     * Analyse les logs pour détecter des tentatives de brute-force
     * @param logs list de toutes les LogEntry
     * @return list d'alertes détectées
     */
    public List<Alert> detect(List<LogEntry> logs) {

        List<Alert> alertes = new ArrayList<>();
        Map<String, List<LogEntry>> byIp = new HashMap<>();

        for (LogEntry log : logs) {
            if (log.getStatusCode() == 401 || log.getStatusCode() == 403) {
                byIp.computeIfAbsent(log.getIpAddress(), k -> new ArrayList<>()).add(log);
            }
        }

        for (String ip : byIp.keySet()) {

            List<LogEntry> entre = byIp.get(ip);
            entre.sort(Comparator.comparing(LogEntry::getTimestamp));

            int debut = 0;

            for (int fin = 0; fin < entre.size(); fin++) {

                while (Duration.between(
                        entre.get(debut).getTimestamp(),
                        entre.get(fin).getTimestamp()).toMinutes() > WINDOW_MINUTES) {
                    debut++;
                }

                int count = fin - debut + 1;

                if (count > 10) {

                    Severity severity =
                            count > 50 ? Severity.HIGH : Severity.MEDIUM;

                    alertes.add(new Alert(
                            ip,
                            severity,
                            "BRUTE_FORCE",
                            "Tentatives de connexion échouées: " + count,
                            entre.get(fin).getTimestamp(),
                            entre.get(fin)
                    ));

                    break;
                }
            }
        }

        return alertes;
    }
}
