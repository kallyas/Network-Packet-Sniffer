package jpcap.packet;

import java.net.InetAddress;
import java.sql.Timestamp;

public class IPPacket extends Packet {
    public int version;
    public int priority;
    public boolean t_flag;
    public boolean r_flag;
    public int length;
    public int ident;
    public boolean dont_frag;
    public boolean more_frag;
    public int offset;
    public int hop_limit;
    public int protocol;
    public int flow_label;
    public InetAddress src_ip;
    public InetAddress dst_ip;

    IPPacket(org.pcap4j.packet.Packet delegate, Timestamp timestamp) {
        super(delegate, timestamp);
    }
}
