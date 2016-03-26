import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


public class IOThread extends Thread {
    private Socket socket = null;
    private ObjectInputStream in = null;
	private ObjectOutputStream out = null;

    private ECPrivateKey ecPrivateKey;
    private ECPublicKey ecPublicKey;
    private byte[] sessionKey;
    private SecretKey secretKey = null;
    private X509Certificate certificate;

    public IOThread(Socket socket) {
        super("IOThread");
        System.out.println("IOThread started");
        this.socket = socket;
        sessionKey = null;
        Security.addProvider(new BouncyCastleProvider());

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
                case "RequestRegistration": {
                    requestRegistration(in, out);
                    break;
                }



                //Test cases
                case "getSessionKey": {
                    out.writeObject(secretKey);
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

    private void requestRegistration(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {
        byte[] encryptedShopname = (byte[])in.readObject();
        byte[] decryptedShopname = Tools.decrypt(encryptedShopname, secretKey);
        String shopName = "";
        for (int j = 0; j < decryptedShopname.length; j++) {
            if (decryptedShopname[j] != (byte)0x00) shopName += (char)decryptedShopname[j];
            else break;
        }
        System.out.println("\nShopname: "+shopName);
        //BigInteger pseudoniem = new BigInteger(128, rand);
        String pseudoString = Tools.generateRandomPseudoniem();
        //byte[] pseudoByteArray = pseudoniem.toByteArray();
        //String pseudoString = new String(pseudoByteArray);
        System.out.println("Generated pseudo: "+pseudoString+" (length: "+pseudoString.length()+")");
        System.out.println("Pseudo byte array length: "+pseudoString.getBytes().length);
        Databank.getInstance().addUser(shopName, pseudoString);
        byte[] pseudo = Tools.encryptMessage(Tools.applyPadding(pseudoString.getBytes()), secretKey);
        out.writeObject(pseudo);
        try {
            X509Certificate pseudoCertificate = generatePseudoCertificate(pseudoString);
            byte[] encryptedCertificate = Tools.encryptMessage(Tools.applyPadding(pseudoCertificate.getEncoded()), secretKey);
            out.writeObject(encryptedCertificate);
            System.out.println("Certificate size: "+pseudoCertificate.getEncoded().length);
            System.out.println("Encrypted certificate size: "+encryptedCertificate.length);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private X509Certificate generatePseudoCertificate(String pseudoString) throws
            KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {
        System.out.println("PseudoString size: "+pseudoString.length());

        // Open keystore and retrieve private key
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String fileNameStore1 = new File("certificates\\LCP.jks").getAbsolutePath();
        char[] password = "LCP".toCharArray();
        FileInputStream fis = new FileInputStream(fileNameStore1);
        keyStore.load(fis, password);
        fis.close();
        PrivateKey privateKeyCA = (PrivateKey) keyStore.getKey("LoyaltyCardProvider", "LCP".toCharArray());
        java.security.cert.Certificate certCA =  keyStore.getCertificate("LoyaltyCardProvider");
        PublicKey publicKeyCA = certCA.getPublicKey();

        // Genereer certificaat voor javacard
        BigInteger serial = BigInteger.valueOf(new Random().nextInt());
        long notUntil = System.currentTimeMillis()+1000L*60*60*24*100;
        X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(Tools.x500Name,
                serial , new Date(System.currentTimeMillis()), new Date(notUntil), new X500Name("CN="+pseudoString+", O=KULeuven, L=Gent, ST=O-Vl, C=BE"), publicKeyCA);
        X509Certificate cert = Tools.signCertificate(v1CertGen, privateKeyCA);
        if (cert != null) {
            cert.checkValidity(new Date());
        }
        cert.verify(publicKeyCA);

        byte[] certificateBytes = cert.getEncoded();
        System.out.println("\nCertificate (length: "+certificateBytes.length+" byte): ");

        return cert;
    }

    private void setupSecureConnection(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException {

        // genereer nieuw EC keypair
        // Niet nodig
        /*CreateStaticKeyPairs.KeyObject keyObject = CreateStaticKeyPairs.createStaticKeyPairs();
        ecPublicKey = (ECPublicKey)keyObject.publicKey;
        ecPrivateKey = (ECPrivateKey)keyObject.privateKey;
        certificate = keyObject.certificate;*/

        out.writeObject(Tools.ECCertificate);


        // Lees certificaat van andere partij in, check of juist en lees public key
        byte[] certificateOtherPartyByteArray = (byte[]) in.readObject();
        X509Certificate certificateOtherParty = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream byteInputStream = new ByteArrayInputStream(certificateOtherPartyByteArray);
            certificateOtherParty = (X509Certificate)certFactory.generateCertificate(byteInputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();

        sessionKey = generateSessionKey(publicKeyOtherParty.getEncoded());
        /*System.out.println("Received W (Public Key other party) (length: "+
                ecPublicKeyOtherPartyBytes.length+" byte): "+
                new BigInteger(1, ecPublicKeyOtherPartyBytes).toString(16));*/



        secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
        System.out.print("SecretKey: ");
        Tools.printByteArray(secretKey.getEncoded());


    }

    private byte[] generateSessionKey(byte[] pubKeyOtherPartyBytes) {
        try {
            PublicKey pubKeyOtherParty = KeyFactory.getInstance("ECDH", "BC")
                .generatePublic(new X509EncodedKeySpec(pubKeyOtherPartyBytes));
            KeyAgreement keyAgr;
            keyAgr = KeyAgreement.getInstance("ECDH", "BC");
            keyAgr.init(Tools.getECPrivateKey());


            keyAgr.doPhase(pubKeyOtherParty, true);
            MessageDigest hash = MessageDigest.getInstance("SHA-1");
            byte[] secret = keyAgr.generateSecret();
            System.out.print("Secret key (length: "+secret.length+"):\t");
            Tools.printByteArray(secret);
            System.out.println();
            byte[] sessionKey = hash.digest(secret);
            sessionKey = Arrays.copyOf(sessionKey, 16);
            System.out.print("Hashed secret key (length: "+sessionKey.length+"):\t");
            Tools.printByteArray(sessionKey);

            return sessionKey;
            }
        catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
        }
return null;
}

}
