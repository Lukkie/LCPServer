import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.Security;


public class Main extends Application {

    /**
     * Loyalty Card Provider Server
     *
     * @param args
     */
	public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        launch(args);
	}

    @Override
    public void start(Stage primaryStage) throws Exception {
        Databank.getInstance();
        int portNumber = 15151;

        FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("LCP.fxml"));
        Parent root = loader.load();
        LCPController controller = loader.getController();
        //controller.setShopName(shopName);
        primaryStage.setTitle("LCP Server");
        Scene rootScene = new Scene(root);
        primaryStage.setScene(rootScene);
        primaryStage.show();
        primaryStage.setOnCloseRequest(e -> {
            Platform.exit();
            System.exit(0);
        });


        new LCPServer(portNumber, controller).start();
    }
}
