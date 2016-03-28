import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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



            /** request registration test **/

            byte[] serialNumber = { (byte)0x1, (byte)0x2 };
            String shopName = "Aldi";
            byte[] shopNameBytes  = shopName.getBytes(StandardCharsets.UTF_8);
            System.out.println("Length: "+shopNameBytes.length);
//            byte[] message = new byte[128];
//            for (int i = 0; i < message.length; i++) {
//                if (i < shopNameBytes.length) message[i] = shopNameBytes[i];
//                else message[i] = new Byte("0");
//            }
            byte[] message = Tools.applyPadding(shopNameBytes);
            byte[] encryptedShopName = Tools.encryptMessage(message, secretKey);
            out.writeObject("RequestRegistration");
            out.writeObject(Tools.encryptMessage(Tools.applyPadding(
                    serialNumber), secretKey));
            out.writeObject(encryptedShopName);

            boolean bestaatAl = (boolean) in.readObject();
            String pseudo = "GebruikerBestaatAl";
            if (!bestaatAl) {
                pseudo = Tools.decryptMessage((byte[]) in.readObject(), secretKey);
                System.out.println("Received pseudo: " + pseudo);

                byte[] pseudoCertificateBytes = Tools.decrypt((byte[]) in.readObject(), secretKey);
                System.out.println("Certificate size: " + pseudoCertificateBytes.length);
            }
            else {
                System.out.println("Gebruiker was al geregistreerd.");
            }


            /** push logs test **/
            out.writeObject("PushLogs");
            ArrayList<byte[]> logs = new ArrayList<byte[]>();
            short amount = (short) 20;
            ByteBuffer buffer = ByteBuffer.allocate(2);
            buffer.putShort(amount);
            System.out.println(buffer.array()[0]+" "+buffer.array()[1]);
            byte[] log = Tools.concatAllBytes(pseudo.getBytes(), buffer.array(), buffer.array()); //stel amount = LP
            System.out.println(log[28] +" "+log[29]);
            logs.add(Tools.encryptMessage(Tools.applyPadding(log), secretKey));
            out.writeObject(logs);




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
