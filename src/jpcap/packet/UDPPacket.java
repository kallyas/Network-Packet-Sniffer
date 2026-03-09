package jpcap.packet;

import java.sql.Timestamp;

public class UDPPacket extends IPPacket {
    public int src_port;
    public int dst_port;

    UDPPacket(org.pcap4j.packet.Packet delegate, Timestamp timestamp) {
        super(delegate, timestamp);
    }
}
