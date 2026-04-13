public class Main {
    public static void main(String[] args) {
        // 1. On simule une ligne de log brute (comme celle du fichier .txt)
        String ligneBrute = "192.168.1.45 - admin [15/Mar/2025:10:23:45 +0100] \"GET /index.html HTTP/1.1\" 200 5423 \"-\" \"Mozilla/5.0\"";

        // 2. On utilise ton constructeur pour créer une fiche vide (objet LogEntry)
        LogEntry log = new LogEntry();

        // 3. On utilise ta méthode de parsing pour remplir la fiche
        log.parseLine(ligneBrute);

        // 4. On vérifie si ça a marché en utilisant tes Getters
        System.out.println("--- Test du Parser (Étudiant A) ---");
        System.out.println("IP détectée   : " + log.getIpAddress());
        System.out.println("Utilisateur   : " + log.getUser());
        System.out.println("Date brute    : " + log.getTimestamp());
        System.out.println("Code HTTP     : " + log.getStatusCode());
        System.out.println("Page visitée  : " + log.getEndpoint());
        System.out.println("Navigateur    : " + log.getUserAgent());
    }
}