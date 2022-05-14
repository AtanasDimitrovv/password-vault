package bg.sofia.uni.fmi.mjt.password.vault.command;

import java.util.List;

public class CommandCreator {
    private static final String REGEX = " ";

    public static Command newCommand(String clientInput, int hashCode) {
        if (clientInput == null) {
            throw new IllegalArgumentException("The string is null");
        }
        List<String> tokens = List.of(clientInput.split(REGEX));
        String[] args = tokens.subList(1, tokens.size()).toArray(new String[0]);

        return new Command(tokens.get(0), args, hashCode);
    }
}
