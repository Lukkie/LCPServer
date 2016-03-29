import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.Security;


public class Main {

    /**
     * Loyalty Card Provider Server
     *
     * @param args
     */
	public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Databank.getInstance();
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
