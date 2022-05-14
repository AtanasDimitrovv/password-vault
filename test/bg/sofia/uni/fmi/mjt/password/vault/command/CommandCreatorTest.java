package bg.sofia.uni.fmi.mjt.password.vault.command;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CommandCreatorTest {
    private static final int HASHCODE = 0;
    private static final String REGEX = " ";

    @Test
    public void testCommandCreationWithInvalidArgument() {
        assertThrows(IllegalArgumentException.class
                , () -> CommandCreator.newCommand(null, HASHCODE), "An exception is expected");
    }

    @Test
    public void testCommandCreationWithNoArguments() {
        String command = "test";
        Command cmd = CommandCreator.newCommand(command, HASHCODE);

        assertEquals(command, cmd.command(), "unexpected command returned for command 'test'");
        assertNotNull(cmd.arguments(), "command arguments should not be null");
        assertEquals(0, cmd.arguments().length, "unexpected command arguments count");
    }

    @Test
    public void testCommandCreationWithOneArgument() {
        String command = "test abcd";
        Command cmd = CommandCreator.newCommand(command, HASHCODE);

        assertEquals(command.split(REGEX)[0], cmd.command()
                , "unexpected command returned for command 'test abcd'");

        assertNotNull(cmd.arguments(), "command arguments should not be null");

        assertEquals(1, cmd.arguments().length, "unexpected command arguments count");

        assertEquals(command.split(REGEX)[1], cmd.arguments()[0]
                , "unexpected argument returned for command 'test abcd'");
    }

}