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

    public void setSerialNumber(byte[] serialNumber) {
        this.serialNumber = serialNumber;
    }

    public void setPseudoniem(String pseudoniem) {
        this.pseudoniem = pseudoniem;
    }

    public void setPoints(int points) {
        this.points = points;
    }

    public byte[] getSerialNumber() {
        return serialNumber;
    }

    public String getPseudoniem() {
        return pseudoniem;
    }

    public int getPoints() {
        return points;
    }
}
