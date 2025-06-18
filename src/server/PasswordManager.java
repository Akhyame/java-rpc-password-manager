package server;

import common.PasswordEntry;
import common.InputValidator;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public class PasswordManager {
    private static final String FILE_PATH = "passwords.txt";
    private List<PasswordEntry> entries = new ArrayList<>();
    private static final String ADMIN_LOGIN = "admin";
    private static final String ADMIN_PASSWORD_HASH = hashPassword("1234");

    public PasswordManager() {
        loadEntries();
    }

    private synchronized void loadEntries() {
        File file = new File(FILE_PATH);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                System.err.println("Erreur création fichier: " + e.getMessage());
            }
        }

        try (BufferedReader br = new BufferedReader(new FileReader(FILE_PATH))) {
            entries = br.lines()
                    .map(PasswordEntry::fromString)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
        } catch (IOException e) {
            System.err.println("Erreur lecture fichier: " + e.getMessage());
        }
    }

    private synchronized void saveEntries() {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(FILE_PATH))) {
            for (PasswordEntry e : entries) {
                bw.write(e.toString());
                bw.newLine();
            }
        } catch (IOException e) {
            System.err.println("Erreur écriture fichier: " + e.getMessage());
        }
    }

    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashed = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashed) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Erreur de hachage", e);
        }
    }

    public boolean authenticate(String login, String password) {
        if (!ADMIN_LOGIN.equals(login)) return false;
        String hashedInput = hashPassword(password);
        return ADMIN_PASSWORD_HASH.equals(hashedInput);
    }

    public synchronized String processCommand(String command) {
        if (command == null || command.trim().isEmpty()) {
            return "ERROR: Commande vide";
        }

        String[] parts = command.split(";");
        if (parts.length == 0) return "ERROR: Commande invalide";

        try {
            switch (parts[0].toUpperCase()) {
                case "ADD":
                    if (parts.length != 4) return "ERROR: Format: ADD;service;username;password";
                    if (!InputValidator.isValidServiceName(parts[1])) return "ERROR: Nom de service invalide";
                    if (!InputValidator.isValidUsername(parts[2])) return "ERROR: Nom d'utilisateur invalide";
                    if (!InputValidator.isValidPassword(parts[3])) return "ERROR: Mot de passe invalide";
                    
                    String hashedPwdAdd = hashPassword(parts[3]);
                    entries.add(new PasswordEntry(parts[1], parts[2], hashedPwdAdd, parts[3]));
                    saveEntries();
                    return "OK: Entrée ajoutée\n" + parts[1] + " - " + parts[2] + " - " + parts[3];

                case "MODIFY":
                    if (parts.length != 4) return "ERROR: Format: MODIFY;service;username;password";
                    if (!InputValidator.isValidServiceName(parts[1])) return "ERROR: Nom de service invalide";
                    if (!InputValidator.isValidUsername(parts[2])) return "ERROR: Nom d'utilisateur invalide";
                    if (!InputValidator.isValidPassword(parts[3])) return "ERROR: Mot de passe invalide";
                    
                    boolean modified = false;
                    String hashedPwdMod = hashPassword(parts[3]);
                    for (PasswordEntry e : entries) {
                        if (e.getService().equalsIgnoreCase(parts[1])) {
                            e.setUsername(parts[2]);
                            e.setPasswordHash(hashedPwdMod);
                            e.setPlainPassword(parts[3]);
                            modified = true;
                        }
                    }
                    saveEntries();
                    return modified ? "OK: Entrée modifiée\n" + parts[1] + " - " + parts[2] + " - " + parts[3] 
                                  : "ERROR: Service non trouvé";

                case "DELETE":
                    if (parts.length != 2) return "ERROR: Format: DELETE;service";
                    if (!InputValidator.isValidServiceName(parts[1])) return "ERROR: Nom de service invalide";
                    
                    boolean removed = entries.removeIf(e -> e.getService().equalsIgnoreCase(parts[1]));
                    saveEntries();
                    return removed ? "OK: Entrée supprimée" : "ERROR: Service non trouvé";

                case "GET_ALL":
                    if (entries.isEmpty()) return "INFO: Aucune entrée trouvée";
                    StringBuilder sb = new StringBuilder();
                    for (PasswordEntry e : entries) {
                        sb.append("Service: ").append(e.getService())
                          .append(" | Utilisateur: ").append(e.getUsername())
                          .append(" | Mot de passe: ").append(e.getPlainPassword() != null ? e.getPlainPassword() : "N/A")
                          .append("\n");
                    }
                    return sb.toString().trim();

                default:
                    return "ERROR: Commande inconnue";
            }
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}