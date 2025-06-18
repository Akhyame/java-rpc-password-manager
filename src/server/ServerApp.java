package server;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import common.InputValidator;

public class ServerApp {
    // Port d'écoute du serveur
    private static final int PORT = 12345;

    // Chemin vers le fichier de clé (keystore) contenant le certificat SSL
    private static final String KEYSTORE_PATH = "server/keystore.jks";

    // Mot de passe pour accéder au keystore
    private static final String KEYSTORE_PASSWORD = "password";

    public static void main(String[] args) {
        try {
            // 1. Crée un contexte SSL en utilisant le protocole TLS
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // 2. Charge le keystore contenant les certificats
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (InputStream keyStoreStream = new FileInputStream(KEYSTORE_PATH)) {
                keyStore.load(keyStoreStream, KEYSTORE_PASSWORD.toCharArray());
            }

            // 3. Initialise le KeyManager pour gérer les clés privées et certificats
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // 4. Initialise le contexte SSL avec les KeyManagers
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            // 5. Crée une socket serveur SSL à partir du contexte
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            try (SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(PORT)) {
                System.out.println("✅ Serveur SSL démarré sur le port " + PORT);

                // 6. Boucle infinie : attend les connexions client
                while (true) {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    // Pour chaque client, on démarre un nouveau thread
                    new Thread(new ClientHandler(clientSocket)).start();
                }
            }
        } catch (Exception e) {
            System.err.println("❌ Erreur serveur : " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Classe interne pour gérer un client dans un thread séparé.
     */
    static class ClientHandler implements Runnable {
        private final SSLSocket socket;
        private final PasswordManager manager = new PasswordManager(); // Gère l'authentification et les commandes

        public ClientHandler(SSLSocket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))
            ) {
                // 🔐 Lire les identifiants du client
                String login = InputValidator.sanitize(in.readLine());
                String password = InputValidator.sanitize(in.readLine());

                // ✅ Vérifie si le format est correct
                if (!InputValidator.isValidUsername(login) || !InputValidator.isValidPassword(password)) {
                    out.write("ERROR: Identifiants invalides");
                    out.newLine();
                    out.flush();
                    return;
                }

                // 🔐 Vérifie si les identifiants sont corrects
                if (!manager.authenticate(login, password)) {
                    out.write("ERROR: Authentification échouée");
                    out.newLine();
                    out.flush();
                    return;
                }

                // ✅ Authentification réussie
                out.write("OK: Authentification réussie");
                out.newLine();
                out.flush();

                // 🔁 Lire et traiter les commandes du client
                String command;
                while ((command = in.readLine()) != null) {
                    String response = manager.processCommand(command); // Gère la commande
                    out.write(response);       // Envoie la réponse
                    out.newLine();             // Nouvelle ligne
                    out.newLine();             // Marqueur de fin de message
                    out.flush();
                }
            } catch (IOException e) {
                System.err.println("❌ Erreur client : " + e.getMessage());
            } finally {
                try {
                    socket.close(); // Ferme la connexion proprement
                } catch (IOException e) {
                    System.err.println("❌ Erreur fermeture socket : " + e.getMessage());
                }
            }
        }
    }
}
