package utils.veriDnsBody;

import java.util.ArrayList;
import java.util.List;

public class VeriDNSBody {
    protected int numberOfAddr;

    protected List<String> branchIPAddr = new ArrayList<>();

    protected String domainName = null;

    protected List<byte[]> IPAddress = new ArrayList<>();

    protected boolean verification;

    protected List<String> maliciousIP = new ArrayList<>();
}