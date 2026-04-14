import java.time.Duration;
import java.util.*;

public class DdosDetect implements ThreatDetector {

    @Override
    public List<Alert> detect(List<LogEntry> logs) {

        List<Alert> alertes = new ArrayList<>();

        if (logs.isEmpty()) return alertes;

        logs.sort(Comparator.comparing(LogEntry::getTimestamp));

        Duration total = Duration.between(
                logs.get(0).getTimestamp(),
                logs.get(logs.size()-1).getTimestamp()
        );

        double avgPerSecond = (double) logs.size() / total.getSeconds();

        Map<String, List<LogEntry>> byIp = new HashMap<>();

        for (LogEntry log : logs) {
            byIp.computeIfAbsent(log.getIp(), k -> new ArrayList<>()).add(log);
        }

        for (String ip : byIp.keySet()) {

            List<LogEntry> entre = byIp.get(ip);
            entre.sort(Comparator.comparing(LogEntry::getTimestamp));

            int debut = 0;

            for (int fin = 0; fin < entre.size(); fin++) {

                while (Duration.between(
                        entre.get(debut).getTimestamp(),
                        entre.get(fin).getTimestamp()).getSeconds() > 10) {
                    debut++;
                }

                int count = fin - debut + 1;
                double rate = count / 10.0;

                if (rate > avgPerSecond * 10) {

                    alertes.add(new Alert(
                            ip,
                            "DDOS",
                            Alert.Severite.HIGH,
                            "Trafic anormal: " + rate + " req/sec",
                            entre.get(fin).getTimestamp()
                    ));

                    break;
                }
            }
        }

        return alertes;
    }
}