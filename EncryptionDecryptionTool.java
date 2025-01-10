import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class EncryptionDecryptionTool {

    private static final String ALGORITHM = "AES";

    // Method to generate a secret key
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(128); // AES key size (128 bits)
        return keyGen.generateKey();
    }

    // Method to encrypt a message
    private static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Method to decrypt a message
    private static String decrypt(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            // Generate a key
            SecretKey secretKey = generateKey();
            System.out.println("Secret Key (Base64 Encoded): " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

            // User input for encryption
            System.out.print("Enter a message to encrypt: ");
            String message = scanner.nextLine();

            // Encrypt the message
            String encryptedMessage = encrypt(message, secretKey);
            System.out.println("Encrypted Message: " + encryptedMessage);

            // Decrypt the message
            String decryptedMessage = decrypt(encryptedMessage, secretKey);
            System.out.println("Decrypted Message: " + decryptedMessage);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
