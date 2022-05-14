package bg.sofia.uni.fmi.mjt.password.vault.storage;

public interface Storage {

    String register(String user, String password);

    String login(String user, String password, int code);

    String logout(int code);

    String addPassword(String website, String user, String password, int code);

    String retrievePassword(String website, String user, int code);

    String removePassword(String website, String user, int code);
}
