/**
 * Created by Lukas on 28-Mar-16.
 */
public class Log {

    User pseudo;
    private short amount;
    private short LP;

    public Log(User pseudo, short amount, short LP) {
        this.pseudo = pseudo;
        this.LP = LP;
        this.amount = amount;
    }

    public User getPseudo() {
        return pseudo;
    }

    public void setPseudo(User pseudo) {
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
