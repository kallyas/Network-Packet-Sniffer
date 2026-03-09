package jpcap;

import jpcap.packet.Packet;

public interface PacketReceiver {
    void receivePacket(Packet packet);
}
