import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.util.ArrayList;
import java.util.List;

public class DnsResponsePacketListener implements PacketListener {
    private List<String> branchIPAddresses = null;

    public DnsResponsePacketListener(List<String> branchIPAddresses) {
        this.branchIPAddresses = branchIPAddresses;
    }

    @Override
    public void gotPacket(PcapPacket packet) {
        // check whether the packet is a dns packet
        if (!packet.contains(DnsPacket.class)) return;

        // check whether the packet is a response packet
        DnsPacket.DnsHeader dnsHeader = packet.get(DnsPacket.class).getHeader(); // get the header of the packet
        if (!dnsHeader.isResponse()) return;

        // check the RR type
        if (dnsHeader.getQuestions().get(0).getQType().compareTo(DnsResourceRecordType.A) != 0) return;

        // get the domain name
        String domainName = dnsHeader.getQuestions().get(0).getQName().getName();

        // check the number of Answers
        if (dnsHeader.getAnCountAsInt() == 0) return;

        // extract all A RRs
        List<byte[]> IPs = new ArrayList<>();
        List<DnsResourceRecord> RRs = dnsHeader.getAnswers();
        for (DnsResourceRecord RR : RRs) {
            if (RR.getDataType().compareTo(DnsResourceRecordType.A) == 0) {
                IPs.add(RR.getRData().getRawData());
            }
        }

        // check the number of A RRs
        if (IPs.isEmpty()) return;

        // process the A RRs
        Thread worker = new Thread(new Worker(domainName, IPs, this.branchIPAddresses));
        worker.setDaemon(true);
        worker.start();
    }
}
