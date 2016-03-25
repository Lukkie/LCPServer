import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Date;


public class TestClient {

	public static void main(String[] args) {
		String hostName = "localhost";
		int portNumber = 15151;

		try (
            Socket socket = new Socket(hostName, portNumber);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            System.out.println("Trying to write to server");
            out.writeObject("SetupSecureConnection");
            System.out.println("Wrote to server");



            byte[] input = (byte[])in.readObject();
            System.out.println("Received bytes");
            for (byte b: input) {
                System.out.print("0x" + String.format("%02x", b) + " ");
            }


            out.writeObject(input); // Dummy: Zend zelfde public key terug
            Thread.sleep(500L);

            out.writeObject("getSessionKey");
            SecretKey secretKey = (SecretKey)in.readObject();
            String shopName = "Kaasfabriek";

            byte[] shopNameBytes  = shopName.getBytes(StandardCharsets.UTF_8);
            System.out.println("Length: "+shopNameBytes.length);
            byte[] message = new byte[128];
            System.arraycopy(shopNameBytes,0,message,0,message.length);
            byte[] encryptedShopName = Tools.encryptMessage(message, secretKey);
            out.writeObject("RequestRegistration");
            out.writeObject(encryptedShopName);





            System.out.println("\nEnding client");
	        } catch (UnknownHostException e) {
	            System.err.println("Don't know about host " + hostName);
	            System.exit(1);
	        } catch (IOException e) {
	            System.err.println("Couldn't get I/O for the connection to " +
	                hostName);
	            System.exit(1);
	        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


    }

}
