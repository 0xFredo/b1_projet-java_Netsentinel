package com.babylon.b1_projetjava_netsentinel;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Main {
    public static void main(String[] args) {

        // --- 1. CHARGEMENT ---
        // On analyse ici le fichier "attack", mais tu peux changer par "clean" pour comparer
        List<LogEntry> logs = chargerLogs("access_log_attack.txt");

        if (logs.isEmpty()) {
            System.err.println("Aucune donnée à analyser.");
            return;
        }

        System.out.println("==========================================");
        System.out.println("       DASHBOARD NETSENTINEL - ANALYSE    ");
        System.out.println("==========================================");

        // --- 2. AFFICHAGE DES 5 OBJECTIFS ---

        // Objectif 1 : Nombre total
        System.out.println("1. Nombre total de requêtes parsées : " + logs.size());

        // Objectif 2 : Top 10 IPs
        System.out.println("\n2. Top 10 des IPs les plus actives :");
        LogAnalyzer.getTopElements(logs, "IP", 10).forEach((k, v) -> System.out.println("   - " + k + " : " + v + " requêtes"));

        // Objectif 3 : Distribution HTTP
        System.out.println("\n3. Distribution des codes HTTP :");
        LogAnalyzer.getHttpStatusDistribution(logs).forEach((k, v) -> System.out.println("   - Code " + k + " : " + v + " fois"));

        // Objectif 4 : Top 10 URLs
        System.out.println("\n4. Top 10 des URLs les plus accédées :");
        LogAnalyzer.getTopElements(logs, "URL", 10).forEach((k, v) -> System.out.println("   - " + k + " : " + v + " accès"));

        // Objectif 5 : Top 5 User-Agents
        System.out.println("\n5. Top 5 des User-Agents :");
        LogAnalyzer.getTopElements(logs, "UA", 5).forEach((k, v) -> System.out.println("   - " + k + " : " + v));

        System.out.println("==========================================");
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
            System.out.println("Fichier [" + nomFichier + "] chargé.");
        } catch (IOException e) {
            System.err.println("Erreur de lecture : " + e.getMessage());
        }
        return liste;
    }
}