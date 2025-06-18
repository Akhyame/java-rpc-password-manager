package common;

public class PasswordEntry {
    private String service;
    private String username;
    private String passwordHash;
    private transient String plainPassword; // Ne sera pas sérialisé

    public PasswordEntry(String service, String username, String passwordHash, String plainPassword) {
        this.service = service;
        this.username = username;
        this.passwordHash = passwordHash;
        this.plainPassword = plainPassword;
    }

    // Getters
    public String getService() { return service; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getPlainPassword() { return plainPassword; }

    // Setters
    public void setUsername(String username) { this.username = username; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public void setPlainPassword(String plainPassword) { this.plainPassword = plainPassword; }

    @Override
    public String toString() {
        return service + ";" + username + ";" + passwordHash;
    }

    public static PasswordEntry fromString(String line) {
        String[] parts = line.split(";");
        if (parts.length == 3) {
            return new PasswordEntry(parts[0], parts[1], parts[2], null);
        }
        return null;
    }
}