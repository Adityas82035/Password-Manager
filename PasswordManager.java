import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

class PasswordEntry {
    String site;
    String hashedPassword;
    String encryptedPassword;
    int strength;

    PasswordEntry(String site, String hashedPassword, String encryptedPassword, int strength) {
        this.site = site;
        this.hashedPassword = hashedPassword;
        this.encryptedPassword = encryptedPassword;
        this.strength = strength;
    }
}

public class PasswordManager extends JFrame {

    private static SecretKey secretKey;
    private static PriorityQueue<PasswordEntry> passwordQueue = new PriorityQueue<>(
        Comparator.comparingInt((PasswordEntry e) -> -e.strength) // Max-Heap by strength
    );

    private JTextField siteField;
    private JPasswordField passwordField;
    private JTextArea outputArea;

    // Static block to initialize AES key
    static {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public PasswordManager() {
        setTitle("Password Manager");
        setSize(500, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel siteLabel = new JLabel("Site:");
        siteField = new JTextField(20);

        JLabel passLabel = new JLabel("Password:");
        passwordField = new JPasswordField(20);
        passwordField.setEchoChar('*');

        JButton addButton = new JButton("Add Password");
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputArea);

        addButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String site = siteField.getText().trim();
                String password = new String(passwordField.getPassword());

                if (site.isEmpty() || password.isEmpty()) {
                    outputArea.append("Site and password cannot be empty.\n");
                    return;
                }

                try {
                    addPassword(site, password);
                    siteField.setText("");
                    passwordField.setText("");
                } catch (Exception ex) {
                    outputArea.append("Error: " + ex.getMessage() + "\n");
                }
            }
        });

        JPanel inputPanel = new JPanel(new GridLayout(3, 2));
        inputPanel.add(siteLabel);
        inputPanel.add(siteField);
        inputPanel.add(passLabel);
        inputPanel.add(passwordField);
        inputPanel.add(new JLabel());
        inputPanel.add(addButton);

        setLayout(new BorderLayout());
        add(inputPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }

    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public static String encryptPassword(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Optional: Add decryption method
    public static String decryptPassword(String encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(encrypted);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }

    public static int evaluateStrength(String password) {
        int score = password.length();
        if (password.matches(".*\\d.*")) score += 5;
        if (password.matches(".*[^a-zA-Z0-9].*")) score += 10;
        if (password.matches(".*[A-Z].*")) score += 5;
        return score;
    }

    public void addPassword(String site, String password) throws Exception {
        String hashed = hashPassword(password);
        String encrypted = encryptPassword(password);
        int strength = evaluateStrength(password);

        passwordQueue.add(new PasswordEntry(site, hashed, encrypted, strength));

        outputArea.append("Added for site: " + site + "\n");
        outputArea.append("Encrypted: " + encrypted + "\n");
        outputArea.append("Strength: " + strength + "\n\n");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new PasswordManager().setVisible(true);
        });
    }
}