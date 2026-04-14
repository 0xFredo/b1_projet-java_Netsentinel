import java.time.LocalDateTime;

public class LogEntry {

    private String ip;
    private LocalDateTime timestamp;
    private String method;
    private String url;
    private int statusCode;
    private String userAgent;

    public LogEntry(String ip,
                    LocalDateTime timestamp,
                    String method,
                    String url,
                    int statusCode,
                    String userAgent) {
        this.ip = ip;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.userAgent = userAgent;
    }

    public String getIp() {
        return ip;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getUserAgent() {
        return userAgent;
    }
}