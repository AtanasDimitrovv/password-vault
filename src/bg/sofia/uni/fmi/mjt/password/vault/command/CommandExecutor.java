package bg.sofia.uni.fmi.mjt.password.vault.command;

import bg.sofia.uni.fmi.mjt.password.vault.storage.Storage;

public class CommandExecutor {

    private static final String REGISTER = "register";
    private static final String LOGIN = "login";
    private static final String LOGOUT = "logout";
    private static final String ADD_PASSWORD = "add-password";
    private static final String RETRIEVE_CREDENTIALS = "retrieve-credentials";
    private static final String REMOVE_PASSWORD = "remove-password";

    private static final String WRONG_NUMBER_OF_PARAMS = "Wrong number of parameters";
    private static final String PASSWORDS_NOT_MATCHING = "The two passwords must match";

    private final Storage storage;

    public CommandExecutor(Storage storage) {
        this.storage = storage;
    }


    public String execute(Command cmd) {
        return switch (cmd.command()) {
            case REGISTER -> register(cmd.arguments());
            case LOGIN -> login(cmd.arguments(), cmd.code());
            case LOGOUT -> logout(cmd.code());
            case ADD_PASSWORD -> addPassword(cmd.arguments(), cmd.code());
            case RETRIEVE_CREDENTIALS -> retrieveCredentials(cmd.arguments(), cmd.code());
            case REMOVE_PASSWORD -> removePassword(cmd.arguments(), cmd.code());
            default -> "Unknown command";
        };
    }

    private String register(String[] args) {
        if (args.length != 3) {
            return WRONG_NUMBER_OF_PARAMS;
        } else if (!args[1].equals(args[2])) {
            return PASSWORDS_NOT_MATCHING;
        }
        return storage.register(args[0], args[1]);
    }

    private String login(String[] args, int code) {
        if (args.length != 2) {
            return WRONG_NUMBER_OF_PARAMS;
        }
        return storage.login(args[0], args[1], code);
    }

    private String logout(int code) {
        return storage.logout(code);
    }

    private String addPassword(String[] args, int code) {
        if (args.length != 3) {
            return WRONG_NUMBER_OF_PARAMS;
        }
        return storage.addPassword(args[0], args[1], args[2], code);
    }

    private String retrieveCredentials(String[] args, int code) {
        if (args.length != 2) {
            return "Wrong number of parameters";
        }
        return storage.retrievePassword(args[0], args[1], code);
    }

    private String removePassword(String[] args, int code) {
        if (args.length != 2) {
            return "Wrong number of parameters";
        }
        return storage.removePassword(args[0], args[1], code);
    }
}
