package models;

import java.time.LocalDateTime;

/**
 * Représente une alerte de sécurité détectée
 */
public class Alert {
    private String ipAddress;
    private Severity severity;
    private String threatType;
    private String description;
    private LocalDateTime timestamp;
    private LogEntry triggeringEntry;

    public Alert(String ipAddress, Severity severity, String threatType, String description, LocalDateTime timestamp, LogEntry triggeringEntry) {
        this.ipAddress = ipAddress;
        this.severity = severity;
        this.threatType = threatType;
        this.description = description;
        this.timestamp = timestamp;
        this.triggeringEntry = triggeringEntry;
    }

    // Getters
    public String getIpAddress() { return ipAddress; }
    public Severity getSeverity() { return severity; }
    public String getThreatType() { return threatType; }
    public String getDescription() { return description; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public LogEntry getTriggeringEntry() { return triggeringEntry; }

    // Setters
    public void setSeverity(Severity severity) { this.severity = severity; }

    @Override
    public String toString() {
        return String.format("[%s] %s - %s (%s) - %s", timestamp, severity.getDisplayName(), threatType, ipAddress, description);
    }
}
