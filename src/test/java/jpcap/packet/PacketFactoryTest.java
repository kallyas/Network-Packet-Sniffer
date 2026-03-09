package jpcap.packet;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.UnknownPacket;

import java.sql.Timestamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

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
}
