package detectors;

import models.Alert;
import models.LogEntry;
import java.util.List;

/**
 * Interface commune pour tous les détecteurs de menaces
 */
public interface ThreatDetector {
    /**
     * Analyse une entrée de log et retourne les alertes détectées
     * @param entry la LogEntry à analyser
     * @param historique l'historique de toutes les entries parsées
     * @return liste des alertes détectées (peut être vide)
     */
    List<Alert> detect(LogEntry entry, List<LogEntry> historique);

    /**
     * Retourne le nom du détecteur
     */
    String getName();
}
