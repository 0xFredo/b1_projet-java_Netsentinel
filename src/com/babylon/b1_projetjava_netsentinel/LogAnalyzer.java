package com.babylon.b1_projetjava_netsentinel;

import java.util.*;
import java.util.stream.Collectors;

public class LogAnalyzer {

    /**
     * Méthode polyvalente pour calculer les Tops (IP, URL, ou User-Agent)
     */
    public static Map<String, Long> getTopElements(List<LogEntry> logs, String type, int limit) {
        Map<String, Long> counts = new HashMap<>();

        for (LogEntry log : logs) {
            String value = "";
            switch (type) {
                case "IP":  value = log.getIpAddress(); break;
                case "URL": value = log.getEndpoint(); break;
                case "UA":  value = log.getUserAgent(); break;
            }

            if (value != null && !value.isEmpty()) {
                counts.put(value, counts.getOrDefault(value, 0L) + 1);
            }
        }

        // Tri décroissant et limitation
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
    public static Map<Integer, Long> getHttpStatusDistribution(List<LogEntry> logs) {
        Map<Integer, Long> stats = new TreeMap<>(); // TreeMap pour que les codes soient triés (200, 404...)
        for (LogEntry log : logs) {
            int code = log.getStatusCode();
            stats.put(code, stats.getOrDefault(code, 0L) + 1);
        }
        return stats;
    }
}