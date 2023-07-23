package utils.veriDnsBody;

import utils.Commons;
import utils.veriDnsHeader.Type;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class VeriDNSRespBody extends VeriDNSBody{
    public VeriDNSRespBody(boolean verification, int numberOfAddr, List<String> maliciousIPs) {
        this.verification = verification;
        this.numberOfAddr = numberOfAddr;
        this.maliciousIP = maliciousIPs;
    }

    public boolean getVerification() {
        return this.verification;
    }

    public int getNumberOfAddr() {
        return this.numberOfAddr;
    }

    public List<String> getMaliciousIPs() {
        return this.maliciousIP;
    }

    public static VeriDNSRespBody parse(InputStream inputStream) throws IOException {
        // read the verification byte
        byte[] verificationRawData = new byte[Commons.Length.VERIFICATION];
        inputStream.read(verificationRawData);
        boolean verification;
        if (verificationRawData[0] == (byte) 1) verification = true;
        else verification = false;

        // read the number of addr and malicious IP(s)
        int numberOfAddr = 0;
        List<String> maliciousIPs = new ArrayList<>();
        if (!verification)
        {
            // read the number of addr
            byte[] numberOfAddrRawData = new byte[Commons.Length.NUMBER_OF_ADDR];
            inputStream.read(numberOfAddrRawData);
            numberOfAddr = ByteBuffer.wrap(numberOfAddrRawData).getInt();

            // check the number of addr
            if (numberOfAddr <= 0) {
                System.err.println("The number of addresses is corrupted in the packet of type " + new Type(Type.VERIDNS_RESP) + ".");
                return null;
            }

            // read the malicious IP(s)
            byte[] maliciousIPsRawData = new byte[numberOfAddr * Commons.Length.IPv4];
            inputStream.read(maliciousIPsRawData);
            for (int i = 0; i < numberOfAddr; i ++) {
                String[] ipFragments = new String[Commons.Length.IPv4];
                for (int j = 0; j < Commons.Length.IPv4; j ++) {
                    ipFragments[j] = Integer.toString(Byte.toUnsignedInt(maliciousIPsRawData[i * Commons.Length.IPv4 + j]));
                }
                maliciousIPs.add(ipFragments[0] + "." +
                                 ipFragments[1] + "." +
                                 ipFragments[2] + "." +
                                 ipFragments[3]);
            }
        }

        return new VeriDNSRespBody(verification, numberOfAddr, maliciousIPs);
    }
}
