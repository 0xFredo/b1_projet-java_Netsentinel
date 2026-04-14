import java.time.LocalDateTime;

public class Alert {

    public enum Severite {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    private String ip;
    private String type;
    private Severite severite;
    private String description;
    private LocalDateTime horaire;

    public String getIp() {
        return ip;
    }

    public String getType() {
        return type;
    }

    public Severite getSeverite() {
        return severite;
    }

    public LocalDateTime getHoraire() {
        return horaire;
    }

    public void setSeverite(Severite severite) {
        this.severite = severite;
    }

    public Alert(String ip, String type, Severite severite, String description, LocalDateTime horaire) {
        this.ip = ip;
        this.type = type;
        this.severite = severite;
        this.description = description;
        this.horaire = horaire;
    }

    @Override
    public String toString() {
        return "[" + severite + "] " + type + " - " + ip + " - " + description;
    }

}