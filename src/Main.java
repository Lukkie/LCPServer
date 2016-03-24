import java.io.IOException;
import java.net.ServerSocket;


public class Main {

    /**
     * Loyalty Card Provider Server
     *
     * @param args
     */
	public static void main(String[] args) {
		int portNumber = 15151;
        IOThread ioThread = null;
		try (ServerSocket serverSocket = new ServerSocket(portNumber)) { 
			System.out.println("Server listening on port "+portNumber);
        	while (true) {       		
                ioThread = new IOThread(serverSocket.accept());
                ioThread.start();
            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
            System.exit(-1);
        }
	}
}
