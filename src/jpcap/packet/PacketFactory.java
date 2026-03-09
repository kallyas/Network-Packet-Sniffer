package jpcap.packet;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;

public final class PacketFactory {

    private static final int ETHERTYPE_ARP = 0x0806;
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int ETHERTYPE_IPV6 = 0x86DD;

    private PacketFactory() {
    }

    public static Packet create(org.pcap4j.packet.Packet delegate, Timestamp timestamp) {
        byte[] raw = delegate.getRawData();
        Packet packet = createPacket(delegate, timestamp, raw);
        packet.datalink = parseEthernet(delegate, timestamp, raw);
        return packet;
    }

    private static Packet createPacket(org.pcap4j.packet.Packet delegate, Timestamp timestamp, byte[] raw) {
        if (raw.length < 14) {
            return new Packet(delegate, timestamp);
        }

        int etherType = unsignedShort(raw, 12);
        if (etherType == ETHERTYPE_ARP) {
            return parseArp(delegate, timestamp, raw);
        }
        if (etherType == ETHERTYPE_IPV4) {
            return parseIpv4(delegate, timestamp, raw);
        }
        if (etherType == ETHERTYPE_IPV6) {
            return parseIpv6(delegate, timestamp, raw);
        }

        return new Packet(delegate, timestamp);
    }

    private static EthernetPacket parseEthernet(org.pcap4j.packet.Packet delegate, Timestamp timestamp, byte[] raw) {
        if (raw.length < 14) {
            return null;
        }
        return new EthernetPacket(
                delegate,
                timestamp,
                unsignedShort(raw, 12),
                formatMac(raw, 6),
                formatMac(raw, 0)
        );
    }

    private static Packet parseArp(org.pcap4j.packet.Packet delegate, Timestamp timestamp, byte[] raw) {
        ARPPacket packet = new ARPPacket(delegate, timestamp);
        if (raw.length < 42) {
            return packet;
        }

        int offset = 14;
        packet.hardtype = unsignedShort(raw, offset);
        packet.prototype = unsignedShort(raw, offset + 2);
        packet.hlen = unsignedByte(raw, offset + 4);
        packet.plen = unsignedByte(raw, offset + 5);
        packet.operation = unsignedShort(raw, offset + 6);
        packet.setSenderHardwareAddress(formatBytes(raw, offset + 8, packet.hlen));
        packet.setSenderProtocolAddress(parseInetAddress(raw, offset + 8 + packet.hlen, packet.plen));
        packet.setTargetHardwareAddress(formatBytes(raw, offset + 8 + packet.hlen + packet.plen, packet.hlen));
        packet.setTargetProtocolAddress(parseInetAddress(raw, offset + 8 + (packet.hlen * 2) + packet.plen, packet.plen));
        return packet;
    }

    private static Packet parseIpv4(org.pcap4j.packet.Packet delegate, Timestamp timestamp, byte[] raw) {
        int offset = 14;
        if (raw.length < offset + 20) {
            return new Packet(delegate, timestamp);
        }

        int headerLength = (raw[offset] & 0x0F) * 4;
        int protocol = unsignedByte(raw, offset + 9);

        if (protocol == 6 && raw.length >= offset + headerLength + 20) {
            TCPPacket packet = new TCPPacket(delegate, timestamp);
            fillIpv4(packet, raw, offset);
            int transportOffset = offset + headerLength;
            packet.src_port = unsignedShort(raw, transportOffset);
            packet.dst_port = unsignedShort(raw, transportOffset + 2);
            packet.sequence = unsignedInt(raw, transportOffset + 4);
            packet.ack_num = unsignedInt(raw, transportOffset + 8);
            int flags = unsignedByte(raw, transportOffset + 13);
            packet.urg = (flags & 0x20) != 0;
            packet.ack = (flags & 0x10) != 0;
            packet.psh = (flags & 0x08) != 0;
            packet.rst = (flags & 0x04) != 0;
            packet.syn = (flags & 0x02) != 0;
            packet.fin = (flags & 0x01) != 0;
            packet.window = unsignedShort(raw, transportOffset + 14);
            return packet;
        }

        if (protocol == 17 && raw.length >= offset + headerLength + 8) {
            UDPPacket packet = new UDPPacket(delegate, timestamp);
            fillIpv4(packet, raw, offset);
            int transportOffset = offset + headerLength;
            packet.src_port = unsignedShort(raw, transportOffset);
            packet.dst_port = unsignedShort(raw, transportOffset + 2);
            packet.length = unsignedShort(raw, transportOffset + 4);
            return packet;
        }

        if (protocol == 1 && raw.length >= offset + headerLength + 8) {
            ICMPPacket packet = new ICMPPacket(delegate, timestamp);
            fillIpv4(packet, raw, offset);
            fillIcmp(packet, raw, offset + headerLength);
            return packet;
        }

        IPPacket packet = new IPPacket(delegate, timestamp);
        fillIpv4(packet, raw, offset);
        return packet;
    }

    private static Packet parseIpv6(org.pcap4j.packet.Packet delegate, Timestamp timestamp, byte[] raw) {
        int offset = 14;
        if (raw.length < offset + 40) {
            return new Packet(delegate, timestamp);
        }

        int nextHeader = unsignedByte(raw, offset + 6);
        if (nextHeader == 6 && raw.length >= offset + 60) {
            TCPPacket packet = new TCPPacket(delegate, timestamp);
            fillIpv6(packet, raw, offset);
            int transportOffset = offset + 40;
            packet.src_port = unsignedShort(raw, transportOffset);
            packet.dst_port = unsignedShort(raw, transportOffset + 2);
            packet.sequence = unsignedInt(raw, transportOffset + 4);
            packet.ack_num = unsignedInt(raw, transportOffset + 8);
            int flags = unsignedByte(raw, transportOffset + 13);
            packet.urg = (flags & 0x20) != 0;
            packet.ack = (flags & 0x10) != 0;
            packet.psh = (flags & 0x08) != 0;
            packet.rst = (flags & 0x04) != 0;
            packet.syn = (flags & 0x02) != 0;
            packet.fin = (flags & 0x01) != 0;
            packet.window = unsignedShort(raw, transportOffset + 14);
            return packet;
        }

        if (nextHeader == 17 && raw.length >= offset + 48) {
            UDPPacket packet = new UDPPacket(delegate, timestamp);
            fillIpv6(packet, raw, offset);
            int transportOffset = offset + 40;
            packet.src_port = unsignedShort(raw, transportOffset);
            packet.dst_port = unsignedShort(raw, transportOffset + 2);
            packet.length = unsignedShort(raw, transportOffset + 4);
            return packet;
        }

        IPPacket packet = new IPPacket(delegate, timestamp);
        fillIpv6(packet, raw, offset);
        return packet;
    }

    private static void fillIpv4(IPPacket packet, byte[] raw, int offset) {
        int tos = unsignedByte(raw, offset + 1);
        int flagsAndOffset = unsignedShort(raw, offset + 6);
        packet.version = 4;
        packet.priority = (tos >> 5) & 0x7;
        packet.t_flag = (tos & 0x08) != 0;
        packet.r_flag = (tos & 0x04) != 0;
        packet.length = unsignedShort(raw, offset + 2);
        packet.ident = unsignedShort(raw, offset + 4);
        packet.dont_frag = (flagsAndOffset & 0x4000) != 0;
        packet.more_frag = (flagsAndOffset & 0x2000) != 0;
        packet.offset = flagsAndOffset & 0x1FFF;
        packet.hop_limit = unsignedByte(raw, offset + 8);
        packet.protocol = unsignedByte(raw, offset + 9);
        packet.src_ip = parseInetAddress(raw, offset + 12, 4);
        packet.dst_ip = parseInetAddress(raw, offset + 16, 4);
    }

    private static void fillIpv6(IPPacket packet, byte[] raw, int offset) {
        int trafficClass = ((raw[offset] & 0x0F) << 4) | ((raw[offset + 1] & 0xF0) >> 4);
        packet.version = 6;
        packet.priority = trafficClass;
        packet.flow_label = ((raw[offset + 1] & 0x0F) << 16) | (unsignedByte(raw, offset + 2) << 8) | unsignedByte(raw, offset + 3);
        packet.length = unsignedShort(raw, offset + 4);
        packet.protocol = unsignedByte(raw, offset + 6);
        packet.hop_limit = unsignedByte(raw, offset + 7);
        packet.src_ip = parseInetAddress(raw, offset + 8, 16);
        packet.dst_ip = parseInetAddress(raw, offset + 24, 16);
    }

    private static void fillIcmp(ICMPPacket packet, byte[] raw, int offset) {
        packet.type = unsignedByte(raw, offset);
        packet.code = unsignedByte(raw, offset + 1);

        if (packet.type == 0 || packet.type == 8 || (packet.type >= 13 && packet.type <= 18)) {
            packet.id = unsignedShort(raw, offset + 4);
            packet.seq = unsignedShort(raw, offset + 6);
        }
        if (packet.type == 5) {
            packet.redir_ip = parseInetAddress(raw, offset + 4, 4);
        }
        if (packet.type == 13 || packet.type == 14) {
            packet.orig_timestamp = unsignedInt(raw, offset + 8);
            packet.recv_timestamp = unsignedInt(raw, offset + 12);
            packet.trans_timestamp = unsignedInt(raw, offset + 16);
        }
        if (packet.type == 17 || packet.type == 18) {
            packet.subnetmask = (int) unsignedInt(raw, offset + 8);
        }
    }

    private static int unsignedByte(byte[] data, int offset) {
        return data[offset] & 0xFF;
    }

    private static int unsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static long unsignedInt(byte[] data, int offset) {
        return ((long) unsignedByte(data, offset) << 24)
                | ((long) unsignedByte(data, offset + 1) << 16)
                | ((long) unsignedByte(data, offset + 2) << 8)
                | unsignedByte(data, offset + 3);
    }

    private static InetAddress parseInetAddress(byte[] data, int offset, int length) {
        if (offset + length > data.length) {
            return null;
        }
        byte[] addr = new byte[length];
        System.arraycopy(data, offset, addr, 0, length);
        try {
            return InetAddress.getByAddress(addr);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static String formatMac(byte[] data, int offset) {
        return formatBytes(data, offset, 6);
    }

    private static String formatBytes(byte[] data, int offset, int length) {
        if (offset + length > data.length) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                builder.append(':');
            }
            String value = Integer.toHexString(data[offset + i] & 0xFF).toUpperCase();
            if (value.length() == 1) {
                builder.append('0');
            }
            builder.append(value);
        }
        return builder.toString();
    }
}
