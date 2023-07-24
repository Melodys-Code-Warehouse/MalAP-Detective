import utils.Commons;
import utils.veriDnsBody.VeriDNSReqBody;
import utils.veriDnsBody.VeriDNSRespBody;
import utils.veriDnsHeader.Type;
import utils.veriDnsHeader.VeriDNSHeader;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.List;

public class Worker implements Runnable {
    private String domainName = null;

    private List<byte[]> IPs = null;

    private List<String> branchIPAddresses = null;

    public Worker(String domainName, List<byte[]> IPs, List<String> branchIPAddresses) {
        this.branchIPAddresses = branchIPAddresses;
        this.IPs = IPs;
        this.domainName = domainName;
    }

    @Override
    public void run() {
        // check the number of local branches
        int numberOfBranches = 0;
        if (this.branchIPAddresses != null) {
            numberOfBranches = this.branchIPAddresses.size();
        }
        if (numberOfBranches == 0) {
            System.err.println("No available local branch servers.");
            return;
        }

        // try branches one by one
        SSLSocket clientSocket = null;
        for (int i = 0; i < numberOfBranches; i ++) {
            clientSocket = Commons.getConfiguredClientSSLSocket(this.branchIPAddresses.get(i), Client.serverPort);
            if (clientSocket != null) {
                // construct the message header
                byte[] sequenceNumberRawData = Commons.getSecureRandomBytes(Commons.Length.SEQUENCE_NUMBER);
                int sequenceNumber = ByteBuffer.wrap(sequenceNumberRawData).getInt();
                // check the reference
                if (IPs == null) {
                    System.err.println("A RRs list points to null.");
                    return;
                }
                VeriDNSHeader requestHeader = new VeriDNSHeader(Type.VERIDNS_REQ,
                        Commons.Length.HEADER_TOTAL + Commons.Length.DOMAIN_NAME +
                                Commons.Length.NUMBER_OF_ADDR + Commons.Length.IPv4 * this.IPs.size(),
                                sequenceNumber);

                // construct the message body
                VeriDNSReqBody requestBody = new VeriDNSReqBody(this.domainName, IPs.size(), IPs);

                // construct the whole packet
                ByteBuffer requestPacket = ByteBuffer.allocate(1 << 10);
                requestPacket.clear();
                requestPacket.put(requestHeader.getRawData());
                requestPacket.put(requestBody.getRawData());
                byte[] requestPacketRawData = new byte[requestPacket.position()];
                requestPacket.flip();
                requestPacket.get(requestPacketRawData);

                // start handshake
                try {
                    clientSocket.startHandshake();
                } catch (IOException e) {
                    System.err.println("Error occurs when sending VeriDNS Request: " + e.getMessage());
                    e.printStackTrace();
                    Commons.closeSocket(clientSocket);
                    break;
                }

                // sent the VeriDNS request message
                try {
                    OutputStream outputStream = clientSocket.getOutputStream();
                    outputStream.write(requestPacketRawData);
                    System.out.println("==========================================");
                    System.out.println("VeriDNS Request:");
                    System.out.println("Domain name: " + requestBody.getDomainName());
                    for (int idx = 0; idx < requestBody.getIPAddress().size(); idx ++) {
                        System.out.println(requestBody.getIPAddress().get(idx));
                    }
                    System.out.println("==========================================\n");
                } catch (IOException e) {
                    System.err.println("Cannot send VeriDns request message: " + e.getMessage());
                    e.printStackTrace();
                    Commons.closeSocket(clientSocket);
                    break;
                }

                // receive the VeriDns response message
                // get the response message
                try {
                    // get the response header
                    InputStream inputStream = clientSocket.getInputStream();
                    VeriDNSHeader responseHeader = VeriDNSHeader.parse(inputStream);

                    // check the response header
                    if (!responseHeader.isHeaderCorrect(new Type(Type.VERIDNS_RESP), sequenceNumber)) {
                        Commons.closeSocket(clientSocket);
                        break;
                    }

                    // get the response body
                    VeriDNSRespBody responseBody = VeriDNSRespBody.parse(inputStream);

                    // print the alert if any record is poisoned
                    if (!responseBody.getVerification()) {
                        System.err.println("==============================");
                        System.err.println(responseBody.getNumberOfAddr() + " poisoned A RR(s) detected!");
                        System.err.println("Domain name: " + requestBody.getDomainName());
                        for (String ip : responseBody.getMaliciousIPs()) {
                            System.err.println(ip);
                        }
                        System.err.println("==============================\n");
                    }
                } catch (IOException e) {
                    System.err.println("Cannot receive the VeriDNS response message: " + e.getMessage());
                    e.printStackTrace();
                    Commons.closeSocket(clientSocket);
                    break;
                }

                // close the socket
                Commons.closeSocket(clientSocket);

                return;
            }
        }

        // error
        System.err.println("Cannot connect to all branch servers.");
        System.exit(1);
    }
}
