package utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

/**
 * Gestionnaire de liste blanche pour éviter les faux positifs
 */
public class WhitelistManager {
    private Set<String> whitelistedIps;
    private final String whitelistFilePath;

    public WhitelistManager(String whitelistFilePath) {
        this.whitelistFilePath = whitelistFilePath;
        this.whitelistedIps = new HashSet<>();
        loadFromFile();
    }

    /**
     * Charge les IPs whitelistées depuis un fichier
     */
    private void loadFromFile() {
        try {
            if (java.nio.file.Files.exists(Paths.get(whitelistFilePath))) {
                java.nio.file.Files.lines(Paths.get(whitelistFilePath))
                    .map(String::trim)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .forEach(whitelistedIps::add);
            }
        } catch (IOException e) {
            System.err.println("Erreur lors de la lecture de la whitelist: " + e.getMessage());
        }
    }

    /**
     * Vérifie si une IP est whitelistée
     */
    public boolean isWhitelisted(String ipAddress) {
        return whitelistedIps.contains(ipAddress);
    }

    /**
     * Ajoute une IP à la whitelist
     */
    public void addToWhitelist(String ipAddress) {
        whitelistedIps.add(ipAddress);
    }

    /**
     * Retourne toutes les IPs whitelistées
     */
    public Set<String> getAllWhitelisted() {
        return new HashSet<>(whitelistedIps);
    }

    /**
     * Sauvegarde la whitelist dans le fichier
     */
    public void saveToFile() {
        try {
            Files.write(Paths.get(whitelistFilePath), whitelistedIps.stream()
                .sorted()
                .map(ip -> ip + "\n")
                .reduce(String::concat)
                .orElse("")
                .getBytes());
        } catch (IOException e) {
            System.err.println("Erreur lors de l'écriture de la whitelist: " + e.getMessage());
        }
    }
}
