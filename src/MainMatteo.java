package com.babylon.b1_projetjava_netsentinel;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Main {
    public static void main(String[] args) {

        // --- 1. CHARGEMENT ---
        List<LogEntry> logs = chargerLogs("access_log_attack.txt");
        Set<String> whitelist = LogAnalyzer.chargerWhitelist("whitelist.txt");

        if (logs.isEmpty()) {
            System.err.println("Aucune donnée à analyser.");
            return;
        }

        System.out.println("\n==========================================");
        System.out.println("       DASHBOARD NETSENTINEL - ANALYSE    ");
        System.out.println("==========================================");

        // 1. Nombre total de requêtes
        System.out.println("1. Nombre total de requêtes parsées : " + logs.size());

        // 2. Top 10 des IPs (En excluant la whitelist)
        System.out.println("\n2. Top 10 des IPs les plus actives (Hors Whitelist) :");
        LogAnalyzer.getTopElements(logs, "IP", 10, whitelist).forEach((k, v) ->
                System.out.println("   - " + k + " : " + v + " requêtes"));

        // 3. Distribution des codes HTTP
        System.out.println("\n3. Distribution des codes HTTP :");
        LogAnalyzer.getHttpStatusDistribution(logs).forEach((k, v) ->
                System.out.println("   - Code " + k + " : " + v + " fois"));

        // 4. Top 10 des URLs les plus accédées
        System.out.println("\n4. Top 10 des URLs les plus accédées :");
        LogAnalyzer.getTopElements(logs, "URL", 10, null).forEach((k, v) ->
                System.out.println("   - " + k + " : " + v + " accès"));

        // 5. Top 5 des User-Agents
        System.out.println("\n5. Top 5 des User-Agents :");
        LogAnalyzer.getTopElements(logs, "UA", 5, null).forEach((k, v) ->
                System.out.println("   - " + k + " : " + v));

        System.out.println("==========================================\n");
    }

    public static List<LogEntry> chargerLogs(String nomFichier) {
        List<LogEntry> liste = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(nomFichier))) {
            String ligne;
            while ((ligne = br.readLine()) != null) {
                if (!ligne.trim().isEmpty()) {
                    LogEntry log = new LogEntry();
                    log.parseLine(ligne);
                    liste.add(log);
                }
            }
            System.out.println("[INFO] Fichier [" + nomFichier + "] chargé.");
        } catch (IOException e) {
            System.err.println("[ERREUR] Impossible de lire : " + nomFichier);
        }
        return liste;
    }
}