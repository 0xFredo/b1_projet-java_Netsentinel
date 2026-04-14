import java.util.*;

public class CorreAlert {

    public static List<Alert> correlate(List<Alert> alertes) {

        Map<String, List<Alert>> byIp = new HashMap<>();

        for (Alert alert : alertes) {
            byIp.computeIfAbsent(alert.getIp(), k -> new ArrayList<>()).add(alert);
        }

        for (String ip : byIp.keySet()) {

            List<Alert> ipAlertes = byIp.get(ip);
            Set<String> types = new HashSet<>();

            for (Alert a : ipAlertes) {
                types.add(a.getType());
            }

            int count = types.size();

            if (count >= 3) {
                for (Alert a : ipAlertes) {
                    a.setSeverite(Alert.Severite.CRITICAL);
                }
            }
            else if (count == 2) {
                for (Alert a : ipAlertes) {
                    a.setSeverite(increaseSeverity(a.getSeverite()));
                }
            }
        }

        return alertes;
    }

    private static Alert.Severite increaseSeverity(Alert.Severite s) {

        switch (s) {
            case LOW: return Alert.Severite.MEDIUM;
            case MEDIUM: return Alert.Severite.HIGH;
            case HIGH: return Alert.Severite.CRITICAL;
            default: return s;
        }
    }
}