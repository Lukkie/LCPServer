import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PBE;

import javax.crypto.KeyAgreement;


public class IOThread extends Thread {
    private Socket socket = null;
    private ObjectInputStream in = null;
	private ObjectOutputStream out = null;

    private ECPrivateKey ecPrivateKey;
    private ECPublicKey ecPublicKey;
    private byte[] sharedKey;

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
		switch(request) {
		    case "SetupSecureConnection": {
            setupSecureConnection(request, in, out);
			break;
		    }

		default: {
			System.out.println("Request not recognized. Stopping connection ");
			return false;
		}
		}
		return true;
		
	}

    private void setupSecureConnection(String request, ObjectInputStream in, ObjectOutputStream out) {
        // generate keys and return public elliptic key
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyPair kp = generateECCKeyPair();
            ecPrivateKey = (ECPrivateKey)kp.getPrivate();
            ecPublicKey = (ECPublicKey)kp.getPublic();
            printSecret(ecPrivateKey);
            printPublic(ecPublicKey);
            byte[] output = kp.getPublic().getEncoded();
            System.out.println("output length: "+output.length);
            out.writeObject(output);
            System.out.println("Bytes are written");
            sharedKey = generateSessionKey(ecPublicKey);

        }
        catch (NoSuchProviderException e) {
            System.out.println("Error: No such provider");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
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
		System.out.println("S (Private Key): "+ new BigInteger(1, key.getD().toByteArray()).toString(16));
	}
	
	public static void printPublic(ECPublicKey key){
		System.out.println("W (Public Key): "+ new BigInteger(1, key.getQ().getEncoded()).toString(16));
	}

    private byte[] generateSessionKey(PublicKey pubKeyOtherParty) {
        try {
            KeyAgreement keyAgr = KeyAgreement.getInstance("ECDH", "BC");
            keyAgr.init(ecPrivateKey);

            keyAgr.doPhase(pubKeyOtherParty, true);

            MessageDigest hash = MessageDigest.getInstance("SHA1");
            byte[] sessionKey = hash.digest(keyAgr.generateSecret());
            System.out.println(new String(sessionKey));

            return sessionKey;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }



}
