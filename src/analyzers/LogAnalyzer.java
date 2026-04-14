package analyzers;

import models.LogEntry;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Analyseur de logs - Statistiques et extraction d'informations
 */
public class LogAnalyzer {

    /**
     * Charge les IPs autorisées depuis un fichier texte.
     */
    public static Set<String> chargerWhitelist(String nomFichier) {
        Set<String> whitelist = new HashSet<>();
        try (BufferedReader br = new BufferedReader(new FileReader(nomFichier))) {
            String ligne;
            while ((ligne = br.readLine()) != null) {
                if (!ligne.trim().isEmpty()) {
                    whitelist.add(ligne.trim());
                }
            }
            System.out.println("[INFO] Whitelist chargée (" + whitelist.size() + " IPs)");
        } catch (IOException e) {
            System.err.println("[AVERTISSEMENT] Aucun fichier whitelist.txt trouvé.");
        }
        return whitelist;
    }

    /**
     * Méthode polyvalente pour calculer les Tops (IP, URL, ou User-Agent)
     * Filtre les IPs si une whitelist est fournie.
     */
    public static Map<String, Long> getTopElements(List<LogEntry> logs, String type, int limit, Set<String> whitelist) {
        Map<String, Long> counts = new HashMap<>();

        for (LogEntry log : logs) {
            String value = "";
            switch (type) {
                case "IP":  value = log.getIpAddress(); break;
                case "URL": value = log.getUrl(); break;
                case "UA":  value = log.getUserAgent(); break;
            }

            // Filtrage : Si c'est une IP et qu'elle est dans la whitelist, on passe à la suivante
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
     * Distribution des codes HTTP.
     */
    public static Map<Integer, Long> getHttpStatusDistribution(List<LogEntry> logs) {
        Map<Integer, Long> stats = new TreeMap<>();
        for (LogEntry log : logs) {
            int code = log.getStatusCode();
            stats.put(code, stats.getOrDefault(code, 0L) + 1);
        }
        return stats;
    }
}
