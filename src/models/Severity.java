package models;

/**
 * Énumération des niveaux de sévérité des alertes
 */
public enum Severity {
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High"),
    CRITICAL("Critical");

    private final String displayName;

    Severity(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * Élève la sévérité d'un niveau
     */
    public Severity elevate() {
        return switch (this) {
            case LOW -> MEDIUM;
            case MEDIUM -> HIGH;
            case HIGH -> CRITICAL;
            case CRITICAL -> CRITICAL;
        };
    }

    /**
     * Retourne la sévérité la plus élevée entre deux
     */
    public static Severity max(Severity s1, Severity s2) {
        return s1.ordinal() > s2.ordinal() ? s1 : s2;
    }
}
