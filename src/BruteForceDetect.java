import java.util.*;
import java.time.Duration;

public class BruteForceDetect implements ThreatDetector{
        private static final int WINDOW_MINUTES = 5;

        @Override
        public List<Alert> detect(List<LogEntry> logs) {

            List<Alert> alertes = new ArrayList<>();
            Map<String, List<LogEntry>> byIp = new HashMap<>();

            for (LogEntry log : logs) {
                if (log.getStatusCode() == 401 || log.getStatusCode() == 403) {
                    byIp.computeIfAbsent(log.getIp(), k -> new ArrayList<>()).add(log);
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

                        Alert.Severite severite =
                                count > 50 ? Alert.Severite.HIGH : Alert.Severite.MEDIUM;

                        alertes.add(new Alert(
                                ip,
                                "BRUTE_FORCE",
                                severite,
                                "Tentatives de connexion échouées: " + count,
                                entre.get(fin).getTimestamp()
                        ));

                        break;
                    }
                }
            }

            return alertes;
        }
}