import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by Lukas on 26-Mar-16.
 */
public class Databank {
    private HashMap<String, ArrayList<User>> users; //shopname, users
    private HashMap<User, ArrayList<Log>> logs; // user, logs
    private HashMap<String, User> pseudoToUser; //Pseudo, User

    private static Databank ourInstance = new Databank();
    public static Databank getInstance() {
        return ourInstance;
    }

    private Databank() {
        users = new HashMap<String, ArrayList<User>>();
        logs = new HashMap<User, ArrayList<Log>>();
        pseudoToUser = new HashMap<String, User>();

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
            User newUser = new User(pseudo, serialNumber, shop);
            users.get(shop).add(newUser);
            logs.put(newUser, new ArrayList<Log>());
            pseudoToUser.put(pseudo, newUser);
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
        try {
            User user = pseudoToUser.get(pseudo);
            logs.get(user).add(new Log(user, amount, LP));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /*public Log getLog(int index) {
        return logs.get(index);
    }

     public int getLogsSize() {
         return logs.size();
     }*/

    public HashMap<User, ArrayList<Log>> getLogs() {
        return logs;
    }

    public Log getLog(String pseudo, int index) {
        User user = pseudoToUser.get(pseudo);
        return logs.get(user).get(index);
    }

    public Log getLog(User user, int index) {
        return logs.get(user).get(index);
    }

    public int getAmountOfLogsForUser(String pseudo) {
        User user = pseudoToUser.get(pseudo);
        return logs.get(user).size();
    }


}
