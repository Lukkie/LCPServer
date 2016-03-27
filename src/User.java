/**
 * Created by Lukas on 26-Mar-16.
 */
public class User {
    private byte[] serialNumber;
    private String pseudoniem;
    private int points;

    public User(String pseudoniem, byte[] serialNumber) {
        this.pseudoniem = pseudoniem;
        this.serialNumber = serialNumber;
        points = 0;
    }
}
