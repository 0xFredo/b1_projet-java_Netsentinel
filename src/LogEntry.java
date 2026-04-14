package com.babylon.b1_projetjava_netsentinel;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogEntry {

    // --- 1. VARIABLES (ATTRIBUTS) ---
    private String ipAddress;
    private String user;
    private String timestamp;
    private String method;
    private String endpoint;
    private String protocol;
    private int statusCode;
    private long responseSize;
    private String referrer;
    private String userAgent;

    // --- 2. LE "MOULE" DE DÉCOUPAGE (REGEX) ---
    private static final Pattern LOG_PATTERN = Pattern.compile(
            "^(\\S+) (\\S+) (\\S+) \\[(.*?)\\] \"(\\S+) (.*?) (.*?)\" (\\d{3}) (\\d+|-) \"(.*?)\" \"(.*?)\"$"
    );

    // --- 3. CONSTRUCTEUR ---
    public LogEntry() {
        // Constructeur vide nécessaire pour créer l'objet avant de le remplir
    }

    // --- 4. MÉTHODE POUR PARSER (TON TRAVAIL - ÉTUDIANT A) ---
    public void parseLine(String line) {
        Matcher matcher = LOG_PATTERN.matcher(line);

        if (matcher.matches()) {
            this.ipAddress = matcher.group(1);
            this.user = matcher.group(3); // On prend l'utilisateur (3ème groupe)
            this.timestamp = matcher.group(4);
            this.method = matcher.group(5);
            this.endpoint = matcher.group(6);
            this.protocol = matcher.group(7);
            this.statusCode = Integer.parseInt(matcher.group(8));

            String sizeStr = matcher.group(9);
            this.responseSize = sizeStr.equals("-") ? 0 : Long.parseLong(sizeStr);

            this.referrer = matcher.group(10);
            this.userAgent = matcher.group(11);
        } else {
            System.err.println("Ligne ignorée (format incorrect) : " + line);
        }
    }

    // --- 5. GETTERS ---
    public String getIpAddress() { return ipAddress; }
    public String getUser() { return user; }
    public String getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getEndpoint() { return endpoint; }
    public int getStatusCode() { return statusCode; }
    public long getResponseSize() { return responseSize; }
    public String getReferrer() { return referrer; }
    public String getUserAgent() { return userAgent; }

    @Override
    public String toString() {
        return "com.babylon.b1_projetjava_netsentinel.LogEntry [IP=" + ipAddress + ", Status=" + statusCode + ", URL=" + endpoint + "]";
    }
}