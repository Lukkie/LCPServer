import java.io.IOException;
import java.net.ServerSocket;

/**
 * Created by Lukas on 30-Mar-16.
 */
public class LCPServer extends Thread {

    private int portNumber;
    private LCPController controller;

    public LCPServer(int portNumber, LCPController controller) {
        super("LCP Server");
        this.portNumber = portNumber;
        this.controller = controller;
    }


    @Override
    public void run() {
        IOThread ioThread = null;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            System.out.println("Server listening on port "+portNumber);
            while (true) {
                ioThread = new IOThread(serverSocket.accept(), controller);
                ioThread.start();
            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
            System.exit(-1);
        }
    }
}
