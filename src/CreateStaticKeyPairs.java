import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Random;

/**
 * Created by Lukas on 17-Mar-16.
 */
public class CreateStaticKeyPairs {

    private static ECPrivateKey ecPrivateKey;
    private static ECPublicKey ecPublicKey;
    private static byte[] sharedKey;
    private static KeyStore keyStore = null;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyPair kp = generateECCKeyPair();
            ecPrivateKey = (ECPrivateKey)kp.getPrivate();
            ecPublicKey = (ECPublicKey)kp.getPublic();
            printSecret(ecPrivateKey);
            printPublic(ecPublicKey);

            generateCertificateForCard(ecPublicKey);
            //byte[] output = kp.getPublic().getEncoded();
            //out.writeObject(output);
            //byte[] pubKeyOtherPartyBytes = (byte[])in.readObject();

            //sharedKey = generateSessionKey(pubKeyOtherPartyBytes);

        }
        catch (NoSuchProviderException e) {
            System.out.println("Error: No such provider");
        }
    }

    private static void generateCertificateForCard(ECPublicKey ecPublicKey) {
        try {
            // Open keystore and retreive private key
            keyStore = KeyStore.getInstance("JKS");
            String fileNameStore1 = new File("certificates\\LCP.jks").getAbsolutePath();
            char[] password = "LCP".toCharArray();
            FileInputStream fis = new FileInputStream(fileNameStore1);
            keyStore.load(fis, password);
            fis.close();
            PrivateKey privateKeyCA = (PrivateKey) keyStore.getKey("LoyaltyCardProvider", "LCP".toCharArray());
            java.security.cert.Certificate certCA = (java.security.cert.Certificate) keyStore.getCertificate("LoyaltyCardProvider");
            PublicKey publicKeyCA = (PublicKey) certCA.getPublicKey();

            // Genereer certificaat voor javacard
            BigInteger serial = BigInteger.valueOf(new Random().nextInt());
            long notUntil = System.currentTimeMillis()+1000L*60*60*24*100;
            X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(new X500Name("CN=www.LCP.be, O=KULeuven, L=Gent, ST=O-Vl, C=BE"),
                    serial , new Date(System.currentTimeMillis()), new Date(notUntil), new X500Name("CN=www.Javacard.be, O=KULeuven, L=Gent, ST=O-Vl, C=BE"), ecPublicKey);
            //X509CertificateHolder holder = v1CertGen.build(signer);
            X509Certificate cert = signCertificate(v1CertGen, privateKeyCA);
            if (cert != null) {
                cert.checkValidity(new Date());
            }
            cert.verify(publicKeyCA);

            byte[] certificateBytes = cert.getEncoded();
            System.out.print("Certificate: ");
            for (byte b: certificateBytes) {
                System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
            }
            System.out.println();


        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableKeyException | SignatureException | NoSuchProviderException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private static X509Certificate signCertificate(X509v1CertificateBuilder v1CertGen, PrivateKey privateKey) {
        try {
            ContentSigner signer = (ContentSigner) new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(v1CertGen.build(signer));
        } catch (OperatorCreationException | CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static KeyPair generateECCKeyPair() throws NoSuchProviderException{
        try{
            ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("prime192v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecParamSpec);
            return kpg.generateKeyPair();
        } catch(NoSuchAlgorithmException | InvalidAlgorithmParameterException e){
            throw new IllegalStateException(e.getLocalizedMessage());
        }
    }

    public static void printSecret(ECPrivateKey key){
        System.out.println("S (Private Key): "+ new BigInteger(1, key.getD().toByteArray()).toString(16));
        byte[] privateKey = key.getEncoded();
        for (byte b: privateKey) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println();
    }

    public static void printPublic(ECPublicKey key){
        System.out.println("W (Public Key): "+ new BigInteger(1, key.getQ().getEncoded()).toString(16));
        byte[] publicKey = key.getEncoded();
        for (byte b: publicKey) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println();
    }
//
//private static byte[] generateSessionKey(byte[] pubKeyOtherPartyBytes) {
//try {
//PublicKey pubKeyOtherParty = KeyFactory.getInstance("ECDH", "BC")
//.generatePublic(new X509EncodedKeySpec(pubKeyOtherPartyBytes));
//KeyAgreement keyAgr = KeyAgreement.getInstance("ECDH", "BC");
//keyAgr.init(ecPrivateKey);
//
//
//keyAgr.doPhase(pubKeyOtherParty, true);
//
//MessageDigest hash = MessageDigest.getInstance("SHA1");
//byte[] sessionKey = hash.digest(keyAgr.generateSecret());
//System.out.print("Hashed secret key:\t");
//for (byte b: sessionKey) {
//System.out.print("0x" + String.format("%02x", b) + " ");
//}
//
//
//return sessionKey;
//} catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | NoSuchProviderException e) {
//e.printStackTrace();
//}
//return null;
//}
}
