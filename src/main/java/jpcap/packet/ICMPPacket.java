package jpcap.packet;

import java.net.InetAddress;
import java.sql.Timestamp;

public class ICMPPacket extends IPPacket {
    public int type;
    public int code;
    public int id;
    public int seq;
    public InetAddress redir_ip;
    public int subnetmask;
    public long orig_timestamp;
    public long recv_timestamp;
    public long trans_timestamp;

    ICMPPacket(org.pcap4j.packet.Packet delegate, Timestamp timestamp) {
        super(delegate, timestamp);
    }
}
