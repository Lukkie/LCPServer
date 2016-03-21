import java.math.BigInteger;
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
/**
 * Created by Lukas on 21-Mar-16.
 */
public class Listing2{

    public static void main(String[] args) throws Exception{
        Security.addProvider(new BouncyCastleProvider());

        KeyPair kp = Listing2.generateECCKeyPair();
        Listing2.printSecret((ECPrivateKey) kp.getPrivate());
        Listing2.printSecret((ECPublicKey) kp.getPublic());
    }

    public static KeyPair generateECCKeyPair() throws NoSuchProviderException{
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
        System.out.println("S (length: "+key.getD().toByteArray().length+" bytes): "+ new BigInteger(1, key.getD().toByteArray()).toString(16));
    }

    public static void printSecret(ECPublicKey key){
        System.out.println("W (length: "+key.getQ().getEncoded().length+" bytes): "+ new BigInteger(1, key.getQ().getEncoded()).toString(16));
    }
}