package utils;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.security.SecureRandom;

public class Commons {
    public static final String[] cipherSuites = new String[]{
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
    };

    public static final String[] protocols = new String[]{"TLSv1.3", "TLSv1.2"};

    public class Length {
        public static final int TYPE = 4;

        public static final int LENGTH = 4;

        public static final int SEQUENCE_NUMBER = 4;

        public static final int HEADER_TOTAL = Commons.Length.TYPE + Commons.Length.LENGTH + Commons.Length.SEQUENCE_NUMBER;

        public static final int NUMBER_OF_ADDR = 4;

        public static final int DOMAIN_NAME = 256;

        public static final int VERIFICATION = 1;

        public static final int IPv4 = 4;
    }
    public static void closeSocket(SSLSocket clientSocket) {
        if (clientSocket != null) {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Cannot close the socket: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    public static byte[] getSecureRandomBytes(int length) {
        SecureRandom secureRandomGenerator = new SecureRandom();
        byte[] bytes = new byte[length];
        secureRandomGenerator.nextBytes(bytes);

        return bytes;
    }

    public static SSLSocket getConfiguredClientSSLSocket(String serverIP, int serverPort) {
        // open the secure socket
        SSLSocket clientSocket = null;
        try {
            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            clientSocket = (SSLSocket) sslSocketFactory.createSocket(serverIP, serverPort);
        } catch (IOException e) {
            System.err.println("Cannot open socket channel: " + e.getMessage());
            e.printStackTrace();
            Commons.closeSocket(clientSocket);
            return null;
        }

        // configure the secure socket
        clientSocket.setEnabledProtocols(Commons.protocols);
        clientSocket.setEnabledCipherSuites(Commons.cipherSuites);

        return clientSocket;
    }
}
