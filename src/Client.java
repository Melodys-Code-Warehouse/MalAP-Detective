import utils.*;
import org.pcap4j.core.*;
import utils.veriDnsBody.BranchServerAddrAnswerBody;
import utils.veriDnsHeader.Type;
import utils.veriDnsHeader.VeriDNSHeader;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.*;

public class Client {
    private String rootServerIP = null;

    public static int serverPort;

    private List<String> branchIPAddresses = null;

    public void launch() {
        System.out.println(
                " __      __       _ _____  _   _  _____        _____ _      _____ ______ _   _ _______ \n" +
                " \\ \\    / /      (_)  __ \\| \\ | |/ ____|      / ____| |    |_   _|  ____| \\ | |__   __|\n" +
                "  \\ \\  / /__ _ __ _| |  | |  \\| | (___ ______| |    | |      | | | |__  |  \\| |  | |   \n" +
                "   \\ \\/ / _ \\ '__| | |  | | . ` |\\___ \\______| |    | |      | | |  __| | . ` |  | |   \n" +
                "    \\  /  __/ |  | | |__| | |\\  |____) |     | |____| |____ _| |_| |____| |\\  |  | |   \n" +
                "     \\/ \\___|_|  |_|_____/|_| \\_|_____/       \\_____|______|_____|______|_| \\_|  |_|   \n" +
                "                                                                                       \n" +
                "                                                                                       ");

        System.out.println("Service starts at " + new Date());

        // obtain the IP address of local branch servers
        this.queryBranchServers();

        // sniff the network
        this.sniff();
    }

    private void queryBranchServers() {
        System.out.println("Querying local branch servers...");

        // get the root server IP and port # from config.properties
        Properties properties = new Properties();
        try (FileInputStream fis = new FileInputStream("config.properties")) {
            properties.load(fis);
            rootServerIP = properties.getProperty("ROOT_IP");
            serverPort = Integer.parseInt(properties.getProperty("ROOT_PORT"), 10);
        } catch (FileNotFoundException e) {
            System.err.println("Cannot find the config file: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        // open and config the secure socket
        SSLSocket clientSocket = Commons.getConfiguredClientSSLSocket(rootServerIP, serverPort);

        // check the secure socket
        if (clientSocket == null) {
            System.err.println("Cannot open secure socket at " + rootServerIP + ".");
            System.exit(1);
        }

        // construct the Branch Server Address Request message
        // generate sequence number
        byte[] sequenceNumberRawData = Commons.getSecureRandomBytes(Commons.Length.SEQUENCE_NUMBER);
        int sequenceNumber = ByteBuffer.wrap(sequenceNumberRawData).getInt();
        // new header object
        VeriDNSHeader queryHeader = new VeriDNSHeader(Type.BRANCH_SERVER_ADDR_QUERY, Commons.Length.HEADER_TOTAL, sequenceNumber);
        // convert the header object to raw data
        byte[] queryPacketRawData = queryHeader.getRawData();

        // send the Branch Server Address Query to the Root Server
        try {
            System.setProperty("javax.net.ssl.trustStore", "C:\\Program Files\\Java\\jdk-19\\lib\\security\\cacerts");
            System.setProperty("javax.net.ssl.trustStorePassword", "changeit"); // Default password for the Java truststore is "changeit"
            System.setProperty("javax.net.ssl.trustStoreType", "JKS");
            System.setProperty("javax.net.ssl.trustStoreAlias", "DOTAGroup8");
            clientSocket.startHandshake();
        } catch (IOException e) {
            System.err.println("Handshake failed: " + e.getMessage());
            e.printStackTrace();
            Commons.closeSocket(clientSocket);
            System.exit(1);
        }


        try {
            OutputStream outputStream = clientSocket.getOutputStream();
            outputStream.write(queryPacketRawData);
        } catch (IOException e) {
            System.err.println("An error occurs when sending Branch Server Address Query to the root server: " + e.getMessage());
            e.printStackTrace();
            Commons.closeSocket(clientSocket);
            System.exit(1);
        }

        // obtain the answer from the root server
        try {
            // get the answer header object
            InputStream inputStream = clientSocket.getInputStream();
            VeriDNSHeader answerHeader = VeriDNSHeader.parse(inputStream);

            // verify the msg
            // verify the type
            if (!answerHeader.isHeaderCorrect(new Type(Type.BRANCH_SERVER_ADDR_ANS), sequenceNumber)) {
                Commons.closeSocket(clientSocket);
                System.exit(1);
            }

            // get the body length
            int bodyLength = answerHeader.getBodyLength();

            // get the answer body object
            BranchServerAddrAnswerBody answerBody = BranchServerAddrAnswerBody.parse(inputStream);
            this.branchIPAddresses = answerBody.getBranchIPAddr();

        } catch (IOException e) {
            System.err.println("An error occurs when receiving Branch Server Address Answer from the root server: " + e.getMessage());
            e.printStackTrace();
            Commons.closeSocket(clientSocket);
            System.exit(1);
        }

        // close the socket
        Commons.closeSocket(clientSocket);
    }

    private void sniff() {
        System.out.println("Please input the IPv4 address of the NIC which will be sniffed: ");
        Scanner scanner = new Scanner(System.in);
        String localhost = scanner.nextLine();

        // sniff the network
        try {
            // Find a network interface for packet capture
            InetAddress addr = InetAddress.getByName(localhost);
            PcapNetworkInterface networkInterface = Pcaps.getDevByAddress(addr);

            // Open the network interface in promiscuous mode with a snapshot length of 65536 bytes and a timeout of 10 milliseconds
            int snapshotLength = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 10;
            PcapHandle handle = networkInterface.openLive(snapshotLength, mode, timeout);

            // Start capturing packets
            int numPackets = -1; // You can change this to the number of packets you want to capture
            PacketListener listener = new DnsResponsePacketListener(this.branchIPAddresses);
            handle.loop(numPackets, listener);

            // Close the handle
            handle.close();

        } catch (PcapNativeException | NotOpenException | InterruptedException | UnknownHostException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.launch();
    }
}
