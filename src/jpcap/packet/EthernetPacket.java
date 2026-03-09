package jpcap.packet;

import java.sql.Timestamp;

public class EthernetPacket extends Packet {
    public int frametype;

    private final String sourceAddress;
    private final String destinationAddress;

    EthernetPacket(org.pcap4j.packet.Packet delegate, Timestamp timestamp, int frametype,
                   String sourceAddress, String destinationAddress) {
        super(delegate, timestamp);
        this.frametype = frametype;
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }

    public String getDestinationAddress() {
        return destinationAddress;
    }
}
