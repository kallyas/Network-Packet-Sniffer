package jpcap.packet;

import java.net.InetAddress;
import java.sql.Timestamp;

public class ARPPacket extends Packet {
    public static final int HARDTYPE_ETHER = 1;
    public static final int HARDTYPE_IEEE802 = 6;
    public static final int HARDTYPE_FRAMERELAY = 15;

    public static final int PROTOTYPE_IP = 0x0800;

    public static final int ARP_REQUEST = 1;
    public static final int ARP_REPLY = 2;
    public static final int RARP_REQUEST = 3;
    public static final int RARP_REPLY = 4;
    public static final int INV_REQUEST = 8;
    public static final int INV_REPLY = 9;

    public int hardtype;
    public int prototype;
    public int hlen;
    public int plen;
    public int operation;

    private String senderHardwareAddress;
    private InetAddress senderProtocolAddress;
    private String targetHardwareAddress;
    private InetAddress targetProtocolAddress;

    ARPPacket(org.pcap4j.packet.Packet delegate, Timestamp timestamp) {
        super(delegate, timestamp);
    }

    void setSenderHardwareAddress(String senderHardwareAddress) {
        this.senderHardwareAddress = senderHardwareAddress;
    }

    void setSenderProtocolAddress(InetAddress senderProtocolAddress) {
        this.senderProtocolAddress = senderProtocolAddress;
    }

    void setTargetHardwareAddress(String targetHardwareAddress) {
        this.targetHardwareAddress = targetHardwareAddress;
    }

    void setTargetProtocolAddress(InetAddress targetProtocolAddress) {
        this.targetProtocolAddress = targetProtocolAddress;
    }

    public Object getSenderHardwareAddress() {
        return senderHardwareAddress;
    }

    public Object getSenderProtocolAddress() {
        return senderProtocolAddress;
    }

    public Object getTargetHardwareAddress() {
        return targetHardwareAddress;
    }

    public Object getTargetProtocolAddress() {
        return targetProtocolAddress;
    }
}
