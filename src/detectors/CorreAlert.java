package detectors;

import java.util.*;
import models.Alert;
import models.Severity;

/**
 * Corrélation d'alertes: augmente la sévérité si plusieurs détecteurs déclenchent pour la même IP
 * - 2 détecteurs: +1 niveau de sévérité
 * - 3+ détecteurs: CRITICAL automatiquement
 */
public class CorreAlert {

    /**
     * Corrèle les alertes par IP et augmente la sévérité selon le nombre de détecteurs
     */
    public static List<Alert> correlate(List<Alert> alertes) {

        Map<String, List<Alert>> byIp = new HashMap<>();

        for (Alert alert : alertes) {
            byIp.computeIfAbsent(alert.getIpAddress(), k -> new ArrayList<>()).add(alert);
        }

        for (String ip : byIp.keySet()) {

            List<Alert> ipAlertes = byIp.get(ip);
            Set<String> types = new HashSet<>();

            for (Alert a : ipAlertes) {
                types.add(a.getThreatType());
            }

            int count = types.size();

            if (count >= 3) {
                for (Alert a : ipAlertes) {
                    a.setSeverity(Severity.CRITICAL);
                }
            }
            else if (count == 2) {
                for (Alert a : ipAlertes) {
                    a.setSeverity(a.getSeverity().elevate());
                }
            }
        }

        return alertes;
    }
}
