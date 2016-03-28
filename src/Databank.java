import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by Lukas on 26-Mar-16.
 */
public class Databank {
    private HashMap<String, ArrayList<User>> users;
    private ArrayList<Log> logs;

    private static Databank ourInstance = new Databank();
    public static Databank getInstance() {
        return ourInstance;
    }

    private Databank() {
        users = new HashMap<String, ArrayList<User>>();
        logs = new ArrayList<Log>();
        File configFile = new File("data\\config.txt");
        try {
            BufferedReader br = new BufferedReader(new FileReader(configFile));
            String s = null;
            int portOfS = 0;
            while ((s = br.readLine()) != null) {
                if (s.charAt(0) == '%') continue;
                String name = s.split("=")[0];
                if (!name.equals("LCP")) {
                    System.out.println("Added shop \""+name+"\" to database.");
                    users.put(name, new ArrayList<User>());
                }
            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void addUser(String shop, String pseudo, byte[] serialNumber) {
        try {
            users.get(shop).add(new User(pseudo, serialNumber));
        } catch(NullPointerException e) {
            throw new NullPointerException("Shop does not exist. Check config file?");
        }
    }

    public boolean shopContainsUser(String shop, byte[] serialNumber) {
        for (User user: users.get(shop)) {
            if (Arrays.equals(user.getSerialNumber(), serialNumber)) return true;

        }
        return false;
    }

    public void addLog(String pseudo, short amount, short LP) {
        logs.add(new Log(pseudo, amount, LP));
    }
}
