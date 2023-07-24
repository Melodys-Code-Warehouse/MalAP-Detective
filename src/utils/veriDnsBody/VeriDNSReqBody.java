package utils.veriDnsBody;

import utils.Commons;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class VeriDNSReqBody extends VeriDNSBody {
    public VeriDNSReqBody(String domainName, int numberOfAddr, List<byte[]> IPAddress) {
        this.domainName = domainName;
        this.numberOfAddr = numberOfAddr;
        this.IPAddress = IPAddress;
    }

    public String getDomainName() {
        return this.domainName;
    }

    public List<String> getIPAddress() {
        List<String> IPStrings = new ArrayList<>();
        for (int i = 0; i < this.IPAddress.size(); i ++) {
            List<String> ipFragments = new ArrayList<>();
            for (int j = 0; j < Commons.Length.IPv4; j ++) {
                ipFragments.add(Integer.toString(Byte.toUnsignedInt((this.IPAddress.get(i))[j])));
            }
            IPStrings.add(ipFragments.get(0) + "." +
                          ipFragments.get(1) + "." +
                          ipFragments.get(2) + "." +
                          ipFragments.get(3));
        }

        return IPStrings;
    }

    public byte[] getRawData() {
        ByteBuffer rawDataBuffer = ByteBuffer.allocate(1 << 10);
        rawDataBuffer.clear();

        // process domain name
        byte[] domainNameRawData = new byte[Commons.Length.DOMAIN_NAME];
        Arrays.fill(domainNameRawData, (byte) 0);
        byte[] domainNameRawDataWithoutTerminator = this.domainName.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(domainNameRawDataWithoutTerminator, 0, domainNameRawData, 0, domainNameRawDataWithoutTerminator.length);
        rawDataBuffer.put(domainNameRawData);

        // process number of addr
        rawDataBuffer.putInt(this.numberOfAddr);

        // process the IP addresses
        for (byte[] IP : this.IPAddress) {
            rawDataBuffer.put(IP);
        }

        byte[] rawData = new byte[rawDataBuffer.position()];
        rawDataBuffer.flip();
        rawDataBuffer.get(rawData);

        return rawData;
    }
}
