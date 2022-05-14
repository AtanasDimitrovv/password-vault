package bg.sofia.uni.fmi.mjt.password.vault.user;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Scanner;

public class User {

    private static final int SERVER_PORT = 7777;
    private static final String SERVER_HOST = "localhost";
    private static final int BUFFER_SIZE = 512;

    private static final ByteBuffer buffer = ByteBuffer.allocateDirect(BUFFER_SIZE);

    public static void main(String[] args) {

        try (SocketChannel socketChannel = SocketChannel.open();
             Scanner scanner = new Scanner(System.in)) {

            socketChannel.connect(new InetSocketAddress(SERVER_HOST, SERVER_PORT));

            System.out.println("Connected to the server.");

            while (true) {
                System.out.print("Enter command: ");
                String message = scanner.nextLine();

                buffer.clear();
                buffer.put(message.getBytes());
                buffer.flip();
                socketChannel.write(buffer);

                buffer.clear();
                socketChannel.read(buffer);
                buffer.flip();

                byte[] byteArray = new byte[buffer.remaining()];
                buffer.get(byteArray);
                String reply = new String(byteArray, "UTF-8");

                System.out.println(reply);
                if (reply.equals("Disconnected")) {
                    break;
                }
            }

        } catch (IOException e) {
            throw new RuntimeException("There is a problem with the network communication", e);
        }
    }
}
