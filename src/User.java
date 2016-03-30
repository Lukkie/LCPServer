import java.util.ArrayList;

/**
 * Created by Lukas on 26-Mar-16.
 */
public class User {
    private byte[] serialNumber;
    private String pseudoniem;
    private int points;
    private String shop;

    public User(String pseudoniem, byte[] serialNumber, String shop) {
        this.pseudoniem = pseudoniem;
        this.serialNumber = serialNumber;
        points = 0;
        this.shop = shop;
    }

    public String getShop() {
        return shop;
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
