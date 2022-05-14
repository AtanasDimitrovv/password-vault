package bg.sofia.uni.fmi.mjt.password.vault.command;


import bg.sofia.uni.fmi.mjt.password.vault.storage.Storage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class CommandExecutorTest {
    private static final String REGISTER = "register";
    private static final String LOGIN = "login";
    private static final String LOGOUT = "logout";
    private static final String ADD_PASSWORD = "add-password";
    private static final String RETRIEVE_CREDENTIALS = "retrieve-credentials";
    private static final String REMOVE_PASSWORD = "remove-password";
    private static final String UNKNOWN = "unknown";
    private static final int HASHCODE = 0;

    private final Storage storageMock = Mockito.mock(Storage.class);

    private final CommandExecutor commandExecutor = new CommandExecutor(storageMock);


    @Test
    public void testExecuteRegisterWithWrongNumberOfParameters() {
        Command reg = new Command(REGISTER, new String[]{"testName", "testPass"}, HASHCODE);
        assertEquals("Wrong number of parameters", commandExecutor.execute(reg)
                , "Unexpected number of parameters");
    }

    @Test
    public void testExecuteRegisterWithDifferentPasswords() {
        Command reg = new Command(REGISTER, new String[]{"testName", "rightPass", "wrongPass"}, HASHCODE);
        assertEquals("The two passwords must match", commandExecutor.execute(reg)
                , "different passwords expected");
    }

    @Test
    public void testExecuteRegisterWithSamePasswords() {
        Command reg = new Command(REGISTER, new String[]{"testName", "rightPass", "rightPass"}, HASHCODE);
        when(storageMock.register("testName", "rightPass")).thenReturn("Successfully registered");
        assertEquals("Successfully registered", commandExecutor.execute(reg)
                , "same passwords expected");
    }

    @Test
    public void testExecuteLoginWithWrongNumberOfParameters() {
        Command login = new Command(LOGIN, new String[]{"testName", "testPass", "testPass"}, HASHCODE);
        assertEquals("Wrong number of parameters", commandExecutor.execute(login)
                , "Unexpected number of parameters");
    }

    @Test
    public void testExecuteLoginWithRegisteredAccount() {
        Command login = new Command(LOGIN, new String[]{"testName", "testPass"}, HASHCODE);
        when(storageMock.login("testName", "testPass", HASHCODE)).thenReturn("Login successful");
        assertEquals("Login successful", commandExecutor.execute(login)
                , "Unexpected problem with logging");
    }

    @Test
    public void testExecuteLogout() {
        Command logout = new Command(LOGOUT, null, HASHCODE);
        when(storageMock.logout(HASHCODE)).thenReturn("Logout successful");
        assertEquals("Logout successful", commandExecutor.execute(logout)
                , "Unexpected problem with logging out");
    }

    @Test
    public void testExecuteAddPasswordWithWrongNumberOfParameters() {
        Command addPass = new Command(ADD_PASSWORD, new String[]{"testWebsite", "testName"}, HASHCODE);
        assertEquals("Wrong number of parameters", commandExecutor.execute(addPass)
                , "Unexpected number of parameters");
    }

    @Test
    public void testExecuteAddPassword() {
        Command addPass = new Command(ADD_PASSWORD, new String[]{"testWebsite", "testName", "testPass"}, HASHCODE);
        when(storageMock.addPassword("testWebsite", "testName", "testPass", HASHCODE))
                .thenReturn("Password successfully added");

        assertEquals("Password successfully added", commandExecutor.execute(addPass)
                , "Unexpected problem with adding password");
    }

    @Test
    public void testExecuteRetrieveCredentialsWithWrongNumberOfParameters() {
        Command retrieveCred = new Command(RETRIEVE_CREDENTIALS, new String[]{"testWebsite"}, HASHCODE);
        assertEquals("Wrong number of parameters", commandExecutor.execute(retrieveCred)
                , "Unexpected number of parameters");
    }

    @Test
    public void testExecuteRetrieveCredentials() {
        Command retrieveCred = new Command(RETRIEVE_CREDENTIALS, new String[]{"testWebsite", "testName"}, HASHCODE);
        when(storageMock.retrievePassword("testWebsite", "testName", HASHCODE)).thenReturn("testPass");
        assertEquals("testPass", commandExecutor.execute(retrieveCred), "Unexpected password");
    }

    @Test
    public void testExecuteRemovePasswordWithWrongNumberOfParameters() {
        Command removePass = new Command(REMOVE_PASSWORD, new String[]{"testWebsite"}, HASHCODE);
        assertEquals("Wrong number of parameters", commandExecutor.execute(removePass)
                , "Unexpected number of parameters");
    }

    @Test
    public void testExecuteRemovePassword() {
        Command removePass = new Command(REMOVE_PASSWORD, new String[]{"testWebsite", "testName"}, HASHCODE);
        when(storageMock.removePassword("testWebsite", "testName", HASHCODE))
                .thenReturn("Password successfully removed");

        assertEquals("Password successfully removed", commandExecutor.execute(removePass)
                , "Unexpected password");
    }

    @Test
    public void testExecuteUnknownCommand() {
        Command unknown = new Command(UNKNOWN, null, HASHCODE);
        assertEquals("Unknown command", commandExecutor.execute(unknown));
    }
}