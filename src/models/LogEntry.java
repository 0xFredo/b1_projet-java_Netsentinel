package models;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Représente une entrée de log Apache Combined Format
 * Format: 192.168.1.45 - - [15/Mar/2025:10:23:45 +0100] "GET /index.html HTTP/1.1" 200 5423 "-" "Mozilla/5.0"
 */
public class LogEntry {
    private static final String LOG_PATTERN = 
        "^([\\d.]+) - ([^ ]*) \\[([^\\]]+)\\] \"([A-Z]+) ([^ ]*) ([^ ]*?)\" (\\d{3}) (\\d+|-) \"([^\"]*)\" \"([^\"]*)\"";
    
    private static final Pattern PATTERN = Pattern.compile(LOG_PATTERN);
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z");

    private String ipAddress;
    private String username;
    private LocalDateTime timestamp;
    private String method;
    private String url;
    private String protocol;
    private int statusCode;
    private long responseSize;
    private String referer;
    private String userAgent;

    private LogEntry() {}

    /**
     * Parse une ligne de log au format Apache Combined
     * @param logLine la ligne de log à parser
     * @return une LogEntry ou null si le parsing échoue
     */
    public static LogEntry parse(String logLine) {
        Matcher matcher = PATTERN.matcher(logLine);
        if (!matcher.matches()) {
            return null;
        }

        LogEntry entry = new LogEntry();
        try {
            entry.ipAddress = matcher.group(1);
            entry.username = matcher.group(2);
            String dateStr = matcher.group(3);
            entry.timestamp = LocalDateTime.parse(dateStr, DATE_FORMAT);
            entry.method = matcher.group(4);
            entry.url = matcher.group(5);
            entry.protocol = matcher.group(6);
            entry.statusCode = Integer.parseInt(matcher.group(7));
            String sizeStr = matcher.group(8);
            entry.responseSize = sizeStr.equals("-") ? 0 : Long.parseLong(sizeStr);
            entry.referer = matcher.group(9);
            entry.userAgent = matcher.group(10);
            return entry;
        } catch (Exception e) {
            return null;
        }
    }

    // Getters
    public String getIpAddress() { return ipAddress; }
    public String getUsername() { return username; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public String getProtocol() { return protocol; }
    public int getStatusCode() { return statusCode; }
    public long getResponseSize() { return responseSize; }
    public String getReferer() { return referer; }
    public String getUserAgent() { return userAgent; }

    @Override
    public String toString() {
        return String.format("%s [%s] %s %s %s %d %d %s",
            ipAddress, timestamp, method, url, protocol, statusCode, responseSize, userAgent);
    }
}
