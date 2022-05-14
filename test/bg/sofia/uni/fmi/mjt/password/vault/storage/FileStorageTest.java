package bg.sofia.uni.fmi.mjt.password.vault.storage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


class FileStorageTest {

    private final Storage storage = new FileStorage();

    private static final int HASHCODE = 0;
    private static final String REGISTER_FILE = "register.txt";
    private static final String TEST_FILE = "testName.txt";

    private void resetFile(String fileName) {
        try (var writer = new FileWriter(fileName)) {
            writer.write("");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @BeforeEach
    public void setUpFiles() {
        resetFile(REGISTER_FILE);
        resetFile(TEST_FILE);
    }

    @Test
    public void testRegisterWithIllegalArguments() {
        assertThrows(IllegalArgumentException.class, () -> storage.register(" ", "1")
                , "An exception is expected");
    }

    @Test
    public void testRegister() {
        assertEquals("Successfully registered", storage.register("testName", "testPass"));
    }

    @Test
    public void testRegisterWithExistingUsername() {
        storage.register("testName1", "testPass1");
        assertEquals("Username is taken. Please choose another one."
                , storage.register("testName1", "testPass2"), "Same username was expected");
    }

    @Test
    public void testLoginWithIllegalArguments() {
        assertThrows(IllegalArgumentException.class, () -> storage.login(" ", "1", HASHCODE)
                , "An exception is expected");
    }

    @Test
    public void testLoginWithNonExistingUsername() {
        assertEquals("No such user", storage.login("testName", "testPass", HASHCODE)
                , "No such username is expected");
    }

    @Test
    public void testLoginWithIncorrectPassword() {
        storage.register("testName", "testPass");
        assertEquals("Wrong password", storage.login("testName", "abcd", HASHCODE)
                , "Different password is expected");
    }

    @Test
    public void testLoginWithAlreadyTakenAccount() {
        storage.register("testName", "testPass");
        storage.login("testName", "testPass", HASHCODE);
        assertEquals("There is already someone logged in that account"
                , storage.login("testName", "testPass", 1)
                , "Another device expected to be logged in");
    }

    @Test
    public void testLogoutWithNonLoggedUser() {
        assertEquals("Must login fist", storage.logout(HASHCODE)
                , "User is expected to not be logged in");
    }

    @Test
    public void testLogoutWithLoggedUser() {
        storage.register("testName", "testPass");
        storage.login("testName", "testPass", HASHCODE);
        assertEquals("Logout successful", storage.logout(HASHCODE)
                , "User is expected to be logged in");
    }

    @Test
    public void testAddPasswordWithIllegalArguments() {
        assertThrows(IllegalArgumentException.class, () ->
                        storage.addPassword("", "testName", "testPass", HASHCODE)
                , "An exception is expected");
    }

    @Test
    public void testAddPasswordWithNotLoggedUser() {
        assertEquals("Must login fist"
                , storage.addPassword("testWebsite", "testName", "testPass", HASHCODE)
                , "User is expected to not be logged in");
    }

    @Test
    public void testAddPasswordWithLoggedUserAndUnsafePass() {
        storage.register("testName", "testPass");
        storage.login("testName", "testPass", HASHCODE);
        assertEquals("Password is not strong enough. Please try another one."
                , storage.addPassword("testWebsite", "testNickname", "testPassword", HASHCODE)
                , "User is expected to be logged in and password is expected to be unsafe");
    }

    @Test
    public void testAddPasswordWithLoggedUserAndSafePassword() {
        storage.register("testName", "testPass");
        storage.login("testName", "testPass", HASHCODE);
        assertEquals("Password successfully added"
                , storage.addPassword("testWebsite", "testNickname", "Str1234onGPass", HASHCODE)
                , "User is expected to be logged in and password is expected to be safe");
    }

    @Test
    public void testRetrievePasswordWithIllegalArguments() {
        assertThrows(IllegalArgumentException.class, () ->
                        storage.retrievePassword("", "testName", HASHCODE)
                , "An exception is expected");
    }

    @Test
    public void testRetrievePasswordWithNotLoggedUser() {
        assertEquals("Must login fist"
                , storage.retrievePassword("testWebsite", "testName", HASHCODE)
                , "User is expected to not be logged in");
    }

    @Test
    public void testRetrievePasswordWithWrongWebsite() {
        storage.register("testName", "testPass");
        storage.login("testName", "testPass", HASHCODE);
        storage.addPassword("testWebsite", "testName", "Str1234onGPass", HASHCODE);
        assertEquals("User does not have registration in this website or is registered with different username"
                , storage.retrievePassword("abc", "testName", HASHCODE)
                , "Different website name is expected");
    }

    @Test
    public void testRetrievePasswordWithLoggedUser() {
        storage.register("testName", "testPass");
        storage.login("testName", "testPass", HASHCODE);
        storage.addPassword("testWebsite", "testName", "Str1234onGPass", HASHCODE);
        assertEquals("Str1234onGPass"
                , storage.retrievePassword("testWebsite", "testName", HASHCODE)
                , "Right password is expected");
    }

    @Test
    public void testRemovePasswordWithIllegalArguments() {
        assertThrows(IllegalArgumentException.class, () ->
                        storage.removePassword("", "testName", HASHCODE)
                , "An exception is expected");
    }

    @Test
    public void testRemovePasswordWithNotLoggedUser() {
        assertEquals("Must login fist"
                , storage.removePassword("testWebsite", "testName", HASHCODE)
                , "User is expected to not be logged in");
    }

    @Test
    public void testRemovePasswordWithLoggedUser() {
        storage.register("testName", "testPass");
        storage.login("testName", "testPass", HASHCODE);
        storage.addPassword("testWebsite", "testName", "Str1234onGPass", HASHCODE);
        storage.addPassword("testWebsite2", "testName2", "Str1234onGPass", HASHCODE);

        boolean hasPass = false;
        boolean doesNotHavePass = false;

        try (var reader = new BufferedReader(new FileReader(TEST_FILE))) {
            hasPass = reader.lines().anyMatch(line -> {
                return (line.split(" ")[0].equals("testWebsite2")
                        && line.split(" ")[1].equals("testName2"));
            });

        } catch (IOException e) {
            e.printStackTrace();
        }

        String result = storage.removePassword("testWebsite2", "testName2", HASHCODE);

        try (var reader = new BufferedReader(new FileReader(TEST_FILE))) {
            doesNotHavePass = reader.lines().noneMatch(line -> {
                return (line.split(" ")[0].equals("testWebsite2")
                        && line.split(" ")[1].equals("testName2"));
            });

        } catch (IOException e) {
            e.printStackTrace();
        }

        assertTrue(hasPass, "Such password is expected");

        assertTrue(doesNotHavePass, "Such password is not expected");

        assertEquals("Password successfully removed", result
                , "Password is expected to be removed");
    }


}