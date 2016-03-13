import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class IOThread extends Thread {
    private Socket socket = null;
    private ObjectInputStream in = null;
	private ObjectOutputStream out = null;

    public IOThread(Socket socket) {
        super("IOThread");
        System.out.println("IOThread started");
        this.socket = socket;
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
		switch(request) {
		case "SetupSecureConnection": {
			// generate keys and return public elliptic key
			Security.addProvider(new BouncyCastleProvider());
			try {
				KeyPair kp = generateECCKeyPair();
				printSecret((ECPrivateKey) kp.getPrivate());
				printSecret((ECPublicKey) kp.getPublic());	
				byte[] output = kp.getPublic().getEncoded();
				System.out.println("output length: "+output.length);
                //out.writeInt(output.length);
				out.writeObject(output);
                System.out.println("Bytes are written");
            }
			catch (NoSuchProviderException e) {
				System.out.println("Error: No such provider");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			break;
		}
		default: {
			System.out.println("Request not recognized. Stopping connection ");
			return false;
		}
		}
		return true;
		
	}
    
	private static KeyPair generateECCKeyPair() throws NoSuchProviderException{
		try{
			ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("prime192v1");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
			kpg.initialize(ecParamSpec);
			return kpg.generateKeyPair();
		} catch(NoSuchAlgorithmException e){
			throw new IllegalStateException(e.getLocalizedMessage());
		} catch(InvalidAlgorithmParameterException e){
			throw new IllegalStateException(e.getLocalizedMessage());
		}
	}
	
	public static void printSecret(ECPrivateKey key){
		System.out.println("S: "+ new BigInteger(1, key.getD().toByteArray()).toString(16));
	}
	
	public static void printSecret(ECPublicKey key){
		System.out.println("W: "+ new BigInteger(1, key.getQ().getEncoded()).toString(16));
	}
    
}
