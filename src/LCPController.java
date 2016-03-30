import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;
import javafx.scene.paint.Color;
import javafx.stage.Window;
import javafx.util.Pair;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Optional;

public class LCPController {


    //private ObservableList<String> logStrings;
    private ObservableList<String> certificateStrings;
    private CertificateParser certificateParser;

    @FXML
    private Tab logsTab;
    @FXML
    private Tab certificatesTab;
    @FXML
    private ListView<String> certificatesList;
    //@FXML
    //private ListView<String> logsList;
    @FXML
    private TabPane root;
    @FXML
    public Accordion accordion;

    public LCPController() {
    }

    @FXML
    public void initialize() {
        certificateParser = new CertificateParser();
        certificateParser.parseCertificates();

        //logStrings = FXCollections.observableArrayList();
        generateLogList();
        generateCertificateList();

        certificatesList.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                if (event.getButton().equals(MouseButton.PRIMARY)) {
                    if (event.getClickCount() == 2) {
                        openCertificate(certificatesList.getSelectionModel().getSelectedIndex());
                    }
                }
            }
        });


        //updateLogs();
    }

    private void generateLogList() {
        //logStrings = FXCollections.observableArrayList();
        HashMap<User, ArrayList<Log>> logs = Databank.getInstance().getLogs();
        ArrayList<TitledPane> panes = new ArrayList<TitledPane>();
        for (User u : logs.keySet()) {
            ListView<String> logsList = new ListView<String>();

            ObservableList<String> logStrings = FXCollections.observableArrayList();
            for (int j = 1; j <= logs.get(u).size(); j++) {
                logStrings.add("Log #" + j);
            }
            logsList.setItems(logStrings);

            logsList.setOnMouseClicked(new EventHandler<MouseEvent>() {
                @Override
                public void handle(MouseEvent event) {
                    if (event.getButton().equals(MouseButton.PRIMARY)) {
                        if (event.getClickCount() == 2) {
                            openLog(u, logsList.getSelectionModel().getSelectedIndex());
                        }
                    }
                }
            });


            TitledPane t = new TitledPane(u.getPseudoniem() + " (Shop: " + u.getShop() + ")", logsList);
            panes.add(t);
        }
        accordion.getPanes().clear();
        accordion.getPanes().addAll(panes);
    }

    public void updateLogs(String pseudo) {
        generateLogList();

    }


    private void generateCertificateList() {
        certificateStrings = FXCollections.observableArrayList();
        certificateStrings.addAll(certificateParser.getCertificateSubjects());

        certificatesList.setItems(certificateStrings);
    }

    private void openLog(User user, int index) {
        Log log = Databank.getInstance().getLog(user, index);
        boolean added = log.getAmount() >= 0;

        Dialog<Pair<String, String>> dialog = new Dialog<>();
        dialog.setTitle("Log");
        dialog.setHeaderText("Viewing log of " + log.getPseudo().getPseudoniem());

        Window window = dialog.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest(event -> window.hide());

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        grid.add(new Label("Pseudo:"), 0, 0);
        grid.add(new Label("" + log.getPseudo().getPseudoniem()), 1, 0);
        grid.add(new Label("Shop:"), 0, 1);
        grid.add(new Label("" + log.getPseudo().getShop()), 1, 1);
        grid.add(new Label("Total LP:"), 0, 2);
        grid.add(new Label("" + log.getLP()), 1, 2);
        if (added) grid.add(new Label("Amount added:"), 0, 3);
        else grid.add(new Label("Amount removed:"), 0, 3);
        grid.add(new Label("" + Math.abs(log.getAmount())), 1, 3);

        dialog.getDialogPane().setContent(grid);

        dialog.showAndWait();
    }

    private void openCertificate(int index) {
        X509Certificate certificate = certificateParser.getCertificate(index);
        boolean revoked = isRevoked(certificate);

        Dialog<Boolean> dialog = new Dialog<>();
        dialog.setTitle("Certificate");
        dialog.setHeaderText("Certificate menu for subject " + certificateStrings.get(index));

        Window window = dialog.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest(event -> window.hide());

        ButtonType revokeButtonType = new ButtonType("Revoke", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(revokeButtonType, ButtonType.CANCEL);

        Node revokeButton = dialog.getDialogPane().lookupButton(revokeButtonType);
        revokeButton.setDisable(revoked);

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));


        grid.add(new Label("Subject:"), 0, 0);
        grid.add(new Label(certificate.getSubjectDN().toString()), 1, 0);

        grid.add(new Label("Issuer:"), 0, 1);
        grid.add(new Label(certificate.getIssuerDN().toString()), 1, 1);

        grid.add(new Label("Valid until:"), 0, 2);
        grid.add(new Label(certificate.getNotAfter().toString()), 1, 2);

        grid.add(new Label("Serial:"), 0, 3);
        grid.add(new Label(certificate.getSerialNumber().toString()), 1, 3);

        grid.add(new Label("Status:"), 0, 4);
        if (revoked) {
            Label l = new Label("REVOKED");
            l.setTextFill(Color.web("#FF0000"));
            grid.add(l, 1, 4);
        } else {
            Label l = new Label("VALID");
            l.setTextFill(Color.web("#00FF00"));
            grid.add(l, 1, 4);
        }

        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == revokeButtonType) {
                return true;
            }
            return null;
        });


        dialog.getDialogPane().setContent(grid);
        Optional<Boolean> result = dialog.showAndWait();

        result.ifPresent(usernamePassword -> {
            if (result.get()) {
                if (!revoked) {
                    revokeCertificate(certificate);
                }
            }
        });
    }

    /**
     * True als revoked
     * False als legit
     */
    private boolean isRevoked(X509Certificate certificate) {

        String hostName = "localhost";
        int portNumber = 26262;


        try (
                Socket socket = new Socket(hostName, portNumber);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            byte[] certificateBytes = certificate.getEncoded();

            System.out.println("Trying to write to OCSP");

            out.writeObject("isCertificateRevoked");
            out.writeObject("LCP");

            //Tools.printByteArray(certificateBytes);
            out.writeObject(certificateBytes);

            //setup secure connection
            X509Certificate certificateOtherParty = Tools.loadCertificate(in, out, false, null);
            out.writeObject(Tools.ECCertificate);

            PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();
            byte[] sessionKey2 = Tools.generateSessionKey(publicKeyOtherParty.getEncoded());
            SecretKey secretKey2 = new SecretKeySpec(sessionKey2, 0, sessionKey2.length, "AES");

            byte[] answerCertificate = Tools.decrypt((byte[])in.readObject(), secretKey2);
            answerCertificate = Arrays.copyOfRange(answerCertificate, 0, certificateBytes.length);
            if (!Arrays.equals(certificateBytes, answerCertificate)) {
                System.out.print("Sent certificate (length: "+certificateBytes.length+"): "); Tools.printByteArray(certificateBytes);
                System.out.print("Received certificate (length: "+answerCertificate.length+"): "); Tools.printByteArray(answerCertificate);

                System.out.println("Middleman detected, assume certificate to be revoked");
                return true;
            }

            byte[] answer = Tools.decrypt((byte[]) in.readObject(), secretKey2);
            System.out.println("Answer = " + answer[0]);
            if (answer[0] == (byte) 0x00) return true; // 0x00 als het revoked is
            else return false;

        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    hostName);
            System.exit(1);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        return true;
    }


    private void revokeCertificate(X509Certificate cert) {

        byte[] certificate = new byte[0];
        try {
            certificate = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        System.out.println("Certificate length: " + certificate.length);

        String hostName = "localhost";
        int portNumber = 26262;


        try (
                Socket socket = new Socket(hostName, portNumber);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {

            out.writeObject("revoke");

            /* Setup secure connection */
            X509Certificate certificateOtherParty = Tools.loadCertificate(in, out, false, null);
            out.writeObject(Tools.ECCertificate);

            PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();
            byte[] sessionKey = Tools.generateSessionKey(publicKeyOtherParty.getEncoded());
            SecretKey secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");

            /* Send certificate */
            out.writeObject(Tools.encryptMessage(Tools.applyPadding(certificate), secretKey));

        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    hostName);
            System.exit(1);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }


}
