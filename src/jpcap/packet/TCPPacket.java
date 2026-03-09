package jpcap.packet;

import java.sql.Timestamp;

public class TCPPacket extends IPPacket {
    public int src_port;
    public int dst_port;
    public long sequence;
    public long ack_num;
    public boolean urg;
    public boolean ack;
    public boolean psh;
    public boolean rst;
    public boolean syn;
    public boolean fin;
    public int window;

    TCPPacket(org.pcap4j.packet.Packet delegate, Timestamp timestamp) {
        super(delegate, timestamp);
    }
}
