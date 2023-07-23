package utils.veriDnsBody;

import utils.Commons;
import utils.veriDnsHeader.Type;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class BranchServerAddrAnswerBody extends VeriDNSBody {
    public BranchServerAddrAnswerBody(int numberOfAddr, List<String> branchIPAddr) {
        this.numberOfAddr = numberOfAddr;
        this.branchIPAddr = branchIPAddr;
    }

    public static BranchServerAddrAnswerBody parse(InputStream inputStream) throws IOException {
        // read the number of addr
        byte[] numberOfAddrRawData = new byte[Commons.Length.NUMBER_OF_ADDR];
        inputStream.read(numberOfAddrRawData);
        int numberOfAddr = ByteBuffer.wrap(numberOfAddrRawData).getInt();

        // check the number of addr
        if (numberOfAddr < 0) {
            System.err.println("Number of Addresses is corrupted in the packet of type "
                                + new Type(Type.BRANCH_SERVER_ADDR_ANS) + ".");

            System.exit(1);
        }

        // read IP addr
        byte[] branchIPAddrRawData = new byte[Commons.Length.IPv4 * numberOfAddr];
        inputStream.read(branchIPAddrRawData);

        List<String> branchIPAddr = new ArrayList<>();
        if (numberOfAddr > 0) {
            for (int i = 0; i < numberOfAddr; i ++) {
                String[] ipFragments = new String[Commons.Length.IPv4];
                for (int j = 0; j < Commons.Length.IPv4; j ++) {
                    ipFragments[j] = Integer.toString(Byte.toUnsignedInt(branchIPAddrRawData[i * Commons.Length.IPv4 + j]));
                }
                branchIPAddr.add(ipFragments[0] + "." +
                                 ipFragments[1] + "." +
                                 ipFragments[2] + "." +
                                 ipFragments[3]);
            }
        }

        return new BranchServerAddrAnswerBody(numberOfAddr, branchIPAddr);
    }

    public int getNumberOfAddr() {
        return this.numberOfAddr;
    }

    public List<String> getBranchIPAddr() {
        return this.branchIPAddr;
    }
}
