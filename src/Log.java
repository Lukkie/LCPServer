/**
 * Created by Lukas on 28-Mar-16.
 */
public class Log {

    String pseudo;
    private short amount;
    private short LP;

    public Log(String pseudo, short amount, short LP) {
        this.pseudo = pseudo;
        this.LP = LP;
        this.amount = amount;
    }

    public String getPseudo() {
        return pseudo;
    }

    public void setPseudo(String pseudo) {
        this.pseudo = pseudo;
    }

    public short getAmount() {
        return amount;
    }

    public void setAmount(short amount) {
        this.amount = amount;
    }

    public short getLP() {
        return LP;
    }

    public void setLP(short LP) {
        this.LP = LP;
    }
}
