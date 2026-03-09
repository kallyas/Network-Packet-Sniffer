package jpcap.packet;

import java.sql.Timestamp;

public class Packet {
    public int len;
    public int caplen;
    public long sec;
    public long usec;
    public byte[] header;
    public byte[] data;
    public Object datalink;

    private final org.pcap4j.packet.Packet delegate;
    private final Timestamp timestamp;

    Packet(org.pcap4j.packet.Packet delegate, Timestamp timestamp) {
        this.delegate = delegate;
        this.timestamp = timestamp;
        byte[] rawData = delegate != null ? delegate.getRawData() : new byte[0];
        this.header = rawData;
        this.data = new byte[0];
        this.len = rawData.length;
        this.caplen = rawData.length;
        if (timestamp != null) {
            this.sec = timestamp.getTime() / 1000L;
            this.usec = timestamp.getNanos() / 1000L;
        }
    }

    public org.pcap4j.packet.Packet getDelegate() {
        return delegate;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public String toString() {
        return delegate != null ? delegate.toString() : super.toString();
    }
}
