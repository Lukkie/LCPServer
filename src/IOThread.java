import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;


public class IOThread extends Thread {
    private Socket socket = null;
    private ObjectInputStream in = null;
	private ObjectOutputStream out = null;

    private ECPrivateKey ecPrivateKey;
    private ECPublicKey ecPublicKey;
    private byte[] sharedKey;
    private X509Certificate certificate;

    public IOThread(Socket socket) {
        super("IOThread");
        System.out.println("IOThread started");
        this.socket = socket;
        sharedKey = null;
    }
	
    
    @Override
    public void run() {     	
    	
    	try {
    		in = new ObjectInputStream(this.socket.getInputStream());
			out = new ObjectOutputStream(this.socket.getOutputStream());
            System.out.println("Waiting for requests.");
            String request;
            while ((request = (String)in.readObject()) != null) {
			    processInput(request, in, out);
            	
			}
            System.out.println("Stopping run method");
        }
    	catch (IOException e) {
            System.out.println("Connection lost, shutting down thread.");
        } catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

    }


	private boolean processInput(String request, ObjectInputStream in,
			ObjectOutputStream out)  {
		System.out.println("Processing request: \""+request+"\"");
        try {
            switch (request) {
                case "SetupSecureConnection": {
                    setupSecureConnection(in, out);
                    break;
                }

                default: {
                    System.out.println("Request not recognized. Stopping connection ");
                    return false;
                }
            }
        }catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return true;
		
	}

    private void setupSecureConnection(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {


        CreateStaticKeyPairs.KeyObject keyObject = CreateStaticKeyPairs.createStaticKeyPairs();
        ecPublicKey = (ECPublicKey)keyObject.publicKey;
        ecPrivateKey = (ECPrivateKey)keyObject.privateKey;
        certificate = keyObject.certificate;


        try {
            out.writeObject(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        byte[] publicKeyOtherParty = (byte[]) in.readObject();

    }


}
