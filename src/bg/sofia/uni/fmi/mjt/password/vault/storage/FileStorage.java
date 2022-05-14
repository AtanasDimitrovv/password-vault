package bg.sofia.uni.fmi.mjt.password.vault.storage;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Base64;


public class FileStorage implements Storage {

    private final Set<String> takenUsernames;
    private final Map<Integer, LocalDateTime> loggedUsers;
    private final Map<Integer, String> userCodes;

    private final String REGISTER_FILE = "register.txt";
    private final String EXCEPTION_FILE = "exceptions.txt";

    private final String CIPHER_PARAM = "AES/CBC/PKCS5Padding";

    private final String REGEX = " ";

    private final String LOGIN_FIRST = "Must login fist";
    private final String ILLEGAL_ARGUMENT = "There is a blank argument";
    private final String COULD_NOT_OPEN_FILE = "Could not open file";
    private final String WRONG_ALGORITHM = "Wrong algorithm used";

    private final String HEADER_NAME = "authorization";
    private final String HEADER_VALUE =
            "basic ZTI3NjAyZWRmZjRlNGNhZWE3NDMzNzE5MzBlMmFhNzQ6Y1luIyp5bmNxNVFAMms/JnNTSndjX3NNYVR3S2JINXo=";
    private final String API = "https://api.enzoic.com/passwords?partial_sha256=";

    private KeyGenerator keygen;
    private final Key key;
    private final IvParameterSpec parameterSpec;

    public FileStorage() {
        this.takenUsernames = new HashSet<>();
        this.loggedUsers = new HashMap<>();
        this.userCodes = new HashMap<>();

        try {
            this.keygen = KeyGenerator.getInstance("AES");
            this.keygen.init(256);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        this.key = keygen.generateKey();
        this.parameterSpec = new IvParameterSpec(new byte[16]);
    }

    private byte[] encrypt(String password) {
        try {
            Cipher encryptionCipher = Cipher.getInstance(CIPHER_PARAM);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            return encryptionCipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

        } catch (NoSuchAlgorithmException e) {
            System.out.println(WRONG_ALGORITHM);
            logException(WRONG_ALGORITHM, e);

        } catch (BadPaddingException | NoSuchPaddingException e) {
            System.out.println("Using algorithm with wrong padding");
            logException("Using algorithm with wrong padding", e);

        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Wrong parameter given to algorithm");
            logException("Wrong parameter given to algorithm", e);

        } catch (IllegalBlockSizeException e) {
            System.out.println("Wrong block size");
            logException("Wrong block size", e);

        } catch (InvalidKeyException e) {
            System.out.println("Invalid key used");
            logException("Invalid key used", e);
        }
        return null;
    }

    private String decrypt(String password) {
        try {
            Cipher decryptionCipher = Cipher.getInstance(CIPHER_PARAM);
            decryptionCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            byte[] decryptedMessageBytes = decryptionCipher.doFinal(Base64.getDecoder().decode(password));
            return new String(decryptedMessageBytes);

        } catch (NoSuchAlgorithmException e) {
            System.out.println(WRONG_ALGORITHM);
            logException(WRONG_ALGORITHM, e);

        } catch (BadPaddingException | NoSuchPaddingException e) {
            System.out.println("Using algorithm with wrong padding");
            logException("Using algorithm with wrong padding", e);

        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Wrong parameter given to algorithm");
            logException("Wrong parameter given to algorithm", e);

        } catch (IllegalBlockSizeException e) {
            System.out.println("Wrong block size");
            logException("Wrong block size", e);

        } catch (InvalidKeyException e) {
            System.out.println("Invalid key used");
            logException("Invalid key used", e);

        }
        return null;
    }

    private String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);

        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }

        return hexString.toString();
    }

    private String getHashed(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(encodedHash);

        } catch (NoSuchAlgorithmException e) {
            System.out.println(WRONG_ALGORITHM);
            logException(WRONG_ALGORITHM, e);
        }

        return null;
    }

    private String takeInfo(String username) {
        try (var reader = new BufferedReader(new FileReader(REGISTER_FILE))) {
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.split(REGEX)[0].equals(username)) {
                    return line;
                }
            }

        } catch (IOException e) {
            System.out.println("could not open registration file");
            logException("could not open registration file", e);
        }

        return null;
    }

    private void logException(String message, Exception e) {
        try (var writer = new FileWriter(EXCEPTION_FILE, true)) {
            e.printStackTrace(new PrintWriter(writer));
            writer.write(message + System.lineSeparator());
            writer.flush();

        } catch (IOException ex) {
            System.out.println("Could not write to file");
        }
    }

    private String checkIfOnline(int code) {
        if (!loggedUsers.containsKey(code)) {
            return LOGIN_FIRST;

        } else if (LocalDateTime.now().isAfter(loggedUsers.get(code).plusMinutes(1))) {
            loggedUsers.remove(code);
            userCodes.remove(code);
            return LOGIN_FIRST;
        }

        return "fine";
    }

    private boolean checkIsPasswordSafe(String password) {
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API + password))
                .header(HEADER_NAME, HEADER_VALUE)
                .build();
        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            System.out.println("There is a problem with web communication.");
            logException("There is a problem with web communication.", e);
            return false;
        }
        return response.statusCode() == 404;
    }

    @Override
    public String register(String username, String password) {
        if (username.isBlank() || password.isBlank()) {
            throw new IllegalArgumentException(ILLEGAL_ARGUMENT);
        }

        if (takenUsernames.contains(username)) {
            return "Username is taken. Please choose another one.";
        }

        try (var writer = new FileWriter(REGISTER_FILE, true)) {
            writer.write(username + " " + getHashed(password) + System.lineSeparator());

        } catch (IOException e) {
            System.out.println(COULD_NOT_OPEN_FILE);
            logException(COULD_NOT_OPEN_FILE, e);
            return "Unable to register. Please try again.";
        }

        takenUsernames.add(username);
        return "Successfully registered";
    }

    @Override
    public String login(String username, String password, int code) {
        if (username.isBlank() || password.isBlank()) {
            throw new IllegalArgumentException(ILLEGAL_ARGUMENT);
        }

        if (!takenUsernames.contains(username)) {
            return "No such user";
        }

        if (userCodes.containsValue(username)) {
            return "There is already someone logged in that account";
        }

        String info = takeInfo(username);
        password = getHashed(password);
        if (!info.split(REGEX)[1].equals(password)) {
            return "Wrong password";
        }

        loggedUsers.put(code, LocalDateTime.now());
        userCodes.put(code, username);
        return "Login successful";
    }

    @Override
    public String logout(int code) {

        if (loggedUsers.containsKey(code)) {
            loggedUsers.remove(code);
            userCodes.remove(code);
            return "Logout successful";
        }

        return LOGIN_FIRST;
    }

    @Override
    public String addPassword(String website, String user, String password, int code) {
        if (website.isBlank() || user.isBlank() || password.isBlank()) {
            throw new IllegalArgumentException(ILLEGAL_ARGUMENT);
        }

        String logged = checkIfOnline(code);
        if (logged.equals(LOGIN_FIRST)) {
            return LOGIN_FIRST;
        }

        if (!checkIsPasswordSafe(getHashed(password).substring(0, 10))) {
            return "Password is not strong enough. Please try another one.";
        }

        try (var writer = new BufferedWriter(new FileWriter(userCodes.get(code) + ".txt", true))) {
            String encryptedPassword = Base64.getEncoder().encodeToString(encrypt(password));
            writer.write(website + " " + user + " " + encryptedPassword + System.lineSeparator());
            writer.flush();

        } catch (IOException e) {
            System.out.println(COULD_NOT_OPEN_FILE);
            logException(COULD_NOT_OPEN_FILE, e);
            return "Unable to add password. Please try again.";
        }

        loggedUsers.put(code, LocalDateTime.now());

        return "Password successfully added";
    }

    @Override
    public String retrievePassword(String website, String user, int code) {
        if (website.isBlank() || user.isBlank()) {
            throw new IllegalArgumentException(ILLEGAL_ARGUMENT);
        }

        String logged = checkIfOnline(code);
        if (logged.equals(LOGIN_FIRST)) {
            return LOGIN_FIRST;
        }

        try (var reader = new BufferedReader(new FileReader(userCodes.get(code) + ".txt"))) {
            String line;

            while ((line = reader.readLine()) != null) {
                String[] tokens = line.split(REGEX);
                if (tokens[0].equals(website) && tokens[1].equals(user)) {
                    return decrypt(tokens[2]);
                }
            }

        } catch (IOException e) {
            System.out.println(COULD_NOT_OPEN_FILE);
            logException(COULD_NOT_OPEN_FILE, e);
            return "Unable to retrieve credentials. Please try again.";
        }

        loggedUsers.put(code, LocalDateTime.now());

        return "User does not have registration in this website or is registered with different username";
    }

    @Override
    public String removePassword(String website, String user, int code) {
        if (website.isBlank() || user.isBlank()) {
            throw new IllegalArgumentException(ILLEGAL_ARGUMENT);
        }

        String logged = checkIfOnline(code);
        if (logged.equals(LOGIN_FIRST)) {
            return LOGIN_FIRST;
        }

        StringBuilder sb = new StringBuilder();
        try (var reader = new BufferedReader(new FileReader(userCodes.get(code) + ".txt"))) {
            String line;

            while ((line = reader.readLine()) != null) {
                String[] tokens = line.split(REGEX);
                if (!tokens[0].equals(website) || !tokens[1].equals(user)) {
                    sb.append(line).append(System.lineSeparator());
                }
            }

        } catch (IOException e) {
            System.out.println(COULD_NOT_OPEN_FILE);
            logException(COULD_NOT_OPEN_FILE, e);
            return "Unable to remove password. Please try again.";
        }

        try (var writer = new BufferedWriter(new FileWriter(userCodes.get(code) + ".txt"))) {
            writer.write(sb.toString());
            writer.flush();

        } catch (IOException e) {
            System.out.println(COULD_NOT_OPEN_FILE);
            logException(COULD_NOT_OPEN_FILE, e);
            return "Unable to remove password. Please try again.";
        }

        loggedUsers.put(code, LocalDateTime.now());
        return "Password successfully removed";
    }
}
