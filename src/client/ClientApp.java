// Ce programme est un client Java qui se connecte de façon sécurisée (SSL)
// à un serveur pour gérer des mots de passe via une interface graphique.

package client;

import javax.net.ssl.*; // SSL pour la sécurité
import javax.swing.*;   // Swing pour l'interface graphique
import java.awt.*;      // Pour les composants graphiques (GridLayout, etc.)
import java.awt.event.*; // Pour gérer les clics sur les boutons
import java.io.*;       // Pour les communications avec le serveur
import java.security.KeyStore; // Pour le chargement du truststore
import common.InputValidator;  // Classe utilitaire pour valider les saisies utilisateur

public class ClientApp {
    // Infos du serveur et fichier de sécurité SSL
    private static final String SERVER_IP = "localhost";
    private static final int SERVER_PORT = 12345;
    private static final String TRUSTSTORE_PATH = "client/truststore.jks";
    private static final String TRUSTSTORE_PASSWORD = "password";

    private BufferedWriter out;
    private BufferedReader in;
    private JFrame frame;

    public static void main(String[] args) {
        // Lance l'interface de connexion dans un thread graphique
        SwingUtilities.invokeLater(() -> new ClientApp().showLoginWindow());
    }

    // Méthode pour se connecter au serveur avec SSL et envoyer login/mot de passe
    private boolean connectToServer(String login, String password) {
        try {
            // Préparation de la connexion SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyStore trustStore = KeyStore.getInstance("JKS");

            // Chargement du truststore contenant le certificat du serveur
            try (InputStream trustStoreStream = new FileInputStream(TRUSTSTORE_PATH)) {
                trustStore.load(trustStoreStream, TRUSTSTORE_PASSWORD.toCharArray());
            }

            // Création des gestionnaires de certificats
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            // Création d'une socket SSL vers le serveur
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(SERVER_IP, SERVER_PORT);
            socket.startHandshake(); // Démarre la connexion sécurisée

            // Préparation des canaux de communication avec le serveur
            out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Envoi des identifiants (login et mot de passe)
            out.write(login);
            out.newLine();
            out.write(password);
            out.newLine();
            out.flush();

            // Réponse du serveur (ex: OK ou ERROR)
            String response = in.readLine();
            return response != null && response.startsWith("OK:");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(frame, "Erreur de connexion : " + e.getMessage(), "Erreur SSL", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    // Affiche la fenêtre de connexion
    private void showLoginWindow() {
        JFrame loginFrame = new JFrame("Connexion");
        JPanel panel = new JPanel(new GridLayout(3, 2, 5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextField usernameField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        JButton loginButton = new JButton("Se connecter");

        // Ajoute les composants à la fenêtre
        panel.add(new JLabel("Nom d'utilisateur:"));
        panel.add(usernameField);
        panel.add(new JLabel("Mot de passe:"));
        panel.add(passwordField);
        panel.add(new JLabel()); // Vide
        panel.add(loginButton);

        // Action quand on clique sur "Se connecter"
        loginButton.addActionListener(e -> {
            String login = InputValidator.sanitize(usernameField.getText());
            String pass = InputValidator.sanitize(new String(passwordField.getPassword()));

            if (!InputValidator.isValidUsername(login)) {
                showError("Nom d'utilisateur invalide\nCaractères autorisés: lettres, chiffres, espaces et -_");
                return;
            }

            if (!InputValidator.isValidPassword(pass)) {
                showError("Mot de passe invalide\nDoit contenir entre 4 et 100 caractères");
                return;
            }

            // Si la connexion est un succès, on passe au menu principal
            if (connectToServer(login, pass)) {
                loginFrame.dispose();
                showMainMenu();
            } else {
                showError("Échec de l'authentification");
            }
        });

        loginFrame.add(panel);
        loginFrame.setSize(350, 180);
        loginFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        loginFrame.setLocationRelativeTo(null);
        loginFrame.setVisible(true);
    }

    // Affiche le menu principal après connexion
    private void showMainMenu() {
        frame = new JFrame("Gestionnaire de mots de passe");
        frame.setLayout(new GridLayout(2, 2, 10, 10));
        frame.getContentPane().setBackground(new Color(240, 240, 240));
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // Boutons pour les différentes actions
        String[] buttonLabels = {"Ajouter", "Modifier", "Supprimer", "Afficher tout"};
        for (String label : buttonLabels) {
            JButton button = new JButton(label);
            button.setFont(new Font("Arial", Font.BOLD, 14));
            button.addActionListener(getButtonListener(label));
            frame.add(button);
        }

        frame.setSize(450, 200);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    // Retourne l'action à faire selon le bouton cliqué
    private ActionListener getButtonListener(String action) {
        return e -> {
            switch (action) {
                case "Ajouter": showAddDialog(); break;
                case "Modifier": showModifyDialog(); break;
                case "Supprimer": showDeleteDialog(); break;
                case "Afficher tout": sendCommand("GET_ALL"); break;
            }
        };
    }

    // Fenêtre pour ajouter un mot de passe
    private void showAddDialog() {
        JTextField service = new JTextField();
        JTextField username = new JTextField();
        JPasswordField password = new JPasswordField();

        Object[] fields = {
            "Service:", service,
            "Nom d'utilisateur:", username,
            "Mot de passe:", password
        };

        int result = JOptionPane.showConfirmDialog(frame, fields, "Ajouter", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            String serviceText = InputValidator.sanitize(service.getText());
            String usernameText = InputValidator.sanitize(username.getText());
            String passwordText = InputValidator.sanitize(new String(password.getPassword()));

            if (!validateEntry(serviceText, usernameText, passwordText)) return;

            sendCommand("ADD;" + serviceText + ";" + usernameText + ";" + passwordText);
        }
    }

    // Fenêtre pour modifier un mot de passe existant
    private void showModifyDialog() {
        JTextField service = new JTextField();
        JTextField username = new JTextField();
        JPasswordField password = new JPasswordField();

        Object[] fields = {
            "Service à modifier:", service,
            "Nouvel utilisateur:", username,
            "Nouveau mot de passe:", password
        };

        int result = JOptionPane.showConfirmDialog(frame, fields, "Modifier", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            String serviceText = InputValidator.sanitize(service.getText());
            String usernameText = InputValidator.sanitize(username.getText());
            String passwordText = InputValidator.sanitize(new String(password.getPassword()));

            if (!validateEntry(serviceText, usernameText, passwordText)) return;

            sendCommand("MODIFY;" + serviceText + ";" + usernameText + ";" + passwordText);
        }
    }

    // Fenêtre pour supprimer un mot de passe
    private void showDeleteDialog() {
        String service = JOptionPane.showInputDialog(frame, "Service à supprimer:", "Suppression", JOptionPane.QUESTION_MESSAGE);
        if (service != null && !service.trim().isEmpty()) {
            String serviceText = InputValidator.sanitize(service);
            if (!InputValidator.isValidServiceName(serviceText)) {
                showError("Nom de service invalide");
                return;
            }
            sendCommand("DELETE;" + serviceText);
        }
    }

    // Vérifie si les champs saisis sont valides
    private boolean validateEntry(String service, String username, String password) {
        if (!InputValidator.isValidServiceName(service)) {
            showError("Service invalide (max 50 caractères)");
            return false;
        }
        if (!InputValidator.isValidUsername(username)) {
            showError("Nom d'utilisateur invalide");
            return false;
        }
        if (!InputValidator.isValidPassword(password)) {
            showError("Mot de passe invalide (4-100 caractères)");
            return false;
        }
        return true;
    }

    // Envoie une commande au serveur
    private void sendCommand(String cmd) {
    try {
        out.write(cmd);
        out.newLine();
        out.flush();

        // Lecture de la réponse
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isEmpty()) break; // Fin de la réponse
            response.append(line).append("\n");
        }

        // Affiche la réponse formatée
        JTextArea textArea = new JTextArea(response.toString());
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(500, 300));
        JOptionPane.showMessageDialog(frame, scrollPane, "Résultats", JOptionPane.INFORMATION_MESSAGE);
    } catch (IOException e) {
        showError("Erreur de communication: " + e.getMessage());
    }
}

    // Mise en forme des messages de réponse
    private String formatResponse(String response) {
        return response.replace(";", " - ")
                       .replace("OK:", "Succès:\n")
                       .replace("ERROR:", "Erreur:\n");
    }

    // Affiche une boîte d'erreur
    private void showError(String message) {
        JOptionPane.showMessageDialog(frame, message, "Erreur", JOptionPane.ERROR_MESSAGE);
    }
}