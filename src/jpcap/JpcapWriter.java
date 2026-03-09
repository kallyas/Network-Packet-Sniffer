package jpcap;

import jpcap.packet.Packet;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapNativeException;

import java.io.IOException;

public class JpcapWriter {

    private final PcapDumper dumper;

    private JpcapWriter(PcapDumper dumper) {
        this.dumper = dumper;
    }

    public static JpcapWriter openDumpFile(JpcapCaptor captor, String path) throws IOException {
        try {
            return new JpcapWriter(captor.dumpOpen(path));
        } catch (PcapNativeException e) {
            throw new IOException("Failed to create dump file: " + path, e);
        } catch (NotOpenException e) {
            throw new IOException("Capture handle is not open", e);
        }
    }

    public void writePacket(Packet packet) throws IOException {
        try {
            dumper.dump(packet.getDelegate(), packet.getTimestamp());
        } catch (NotOpenException e) {
            throw new IOException("Dump file is not open", e);
        }
    }

    public void close() {
        if (dumper != null) {
            dumper.close();
        }
    }
}
