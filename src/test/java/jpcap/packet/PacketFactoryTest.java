package jpcap.packet;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.UnknownPacket;

import java.sql.Timestamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

class PacketFactoryTest {

    @Test
    void parsesIpv4TcpPacketIntoLegacyCompatibilityType() {
        byte[] raw = new byte[] {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x00, 0x11, 0x22, 0x33,
                0x08, 0x00,
                0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00,
                0x40, 0x06, 0x00, 0x00,
                (byte) 192, (byte) 168, 1, 10,
                (byte) 192, (byte) 168, 1, 20,
                0x04, (byte) 0xD2, 0x00, 0x50,
                0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x02,
                0x50, 0x12, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x00
        };

        Packet packet = PacketFactory.create(
                UnknownPacket.newPacket(raw, 0, raw.length),
                new Timestamp(1_700_000_000_000L)
        );

        TCPPacket tcpPacket = assertInstanceOf(TCPPacket.class, packet);
        assertEquals(1234, tcpPacket.src_port);
        assertEquals(80, tcpPacket.dst_port);
        assertEquals(4, tcpPacket.version);
        assertEquals(6, tcpPacket.protocol);
        assertEquals("192.168.1.10", tcpPacket.src_ip.getHostAddress());
        assertEquals("192.168.1.20", tcpPacket.dst_ip.getHostAddress());
    }

    @Test
    void parsesIpv6UdpPacketIntoLegacyCompatibilityType() {
        byte[] raw = new byte[] {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x00, 0x11, 0x22, 0x33,
                (byte) 0x86, (byte) 0xDD,
                0x60, 0x00, 0x00, 0x00,
                0x00, 0x08, 0x11, 0x40,
                0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                0x13, (byte) 0x88, 0x00, 0x35,
                0x00, 0x08, 0x00, 0x00
        };

        Packet packet = PacketFactory.create(
                UnknownPacket.newPacket(raw, 0, raw.length),
                new Timestamp(1_700_000_000_000L)
        );

        UDPPacket udpPacket = assertInstanceOf(UDPPacket.class, packet);
        assertEquals(5000, udpPacket.src_port);
        assertEquals(53, udpPacket.dst_port);
        assertEquals(6, udpPacket.version);
        assertEquals(17, udpPacket.protocol);
        assertEquals("2001:db8:0:0:0:0:0:1", udpPacket.src_ip.getHostAddress());
        assertEquals("2001:db8:0:0:0:0:0:2", udpPacket.dst_ip.getHostAddress());
    }

    @Test
    void parsesArpPacketIntoLegacyCompatibilityType() {
        byte[] raw = new byte[] {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                0x00, 0x0c, 0x29, 0x3e, 0x5c, 0x6d,
                0x08, 0x06,
                0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
                0x00, 0x0c, 0x29, 0x3e, 0x5c, 0x6d,
                (byte) 192, (byte) 168, 1, 10,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                (byte) 192, (byte) 168, 1, 1
        };

        Packet packet = PacketFactory.create(
                UnknownPacket.newPacket(raw, 0, raw.length),
                new Timestamp(1_700_000_000_000L)
        );

        ARPPacket arpPacket = assertInstanceOf(ARPPacket.class, packet);
        assertEquals(ARPPacket.ARP_REQUEST, arpPacket.operation);
        assertEquals(ARPPacket.HARDTYPE_ETHER, arpPacket.hardtype);
        assertEquals(ARPPacket.PROTOTYPE_IP, arpPacket.prototype);
        assertEquals("00:0C:29:3E:5C:6D", arpPacket.getSenderHardwareAddress());
        assertEquals("192.168.1.10", arpPacket.getSenderProtocolAddress().toString().replaceFirst("^.*/", ""));
    }

    @Test
    void fallsBackToBasePacketForMalformedFrames() {
        byte[] raw = new byte[] {0x01, 0x02, 0x03};

        Packet packet = PacketFactory.create(
                UnknownPacket.newPacket(raw, 0, raw.length),
                new Timestamp(1_700_000_000_000L)
        );

        assertInstanceOf(Packet.class, packet);
        assertEquals(3, packet.len);
        assertNull(packet.datalink);
    }
}
