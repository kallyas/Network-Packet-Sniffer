package jpcap;

import jpcap.packet.Packet;
import jpcap.packet.PacketFactory;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.EOFException;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class JpcapCaptor {

    private static String lastDeviceListError;

    private final PcapHandle handle;
    private volatile boolean breakRequested;

    private JpcapCaptor(PcapHandle handle) {
        this.handle = handle;
    }

    public static NetworkInterface[] getDeviceList() {
        try {
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            lastDeviceListError = null;
            if (devices == null) {
                return null;
            }

            List<NetworkInterface> wrapped = new ArrayList<NetworkInterface>(devices.size());
            for (PcapNetworkInterface device : devices) {
                wrapped.add(new NetworkInterface(device));
            }
            return wrapped.toArray(new NetworkInterface[0]);
        } catch (UnsatisfiedLinkError e) {
            lastDeviceListError = buildNativeLoadMessage(e);
            return null;
        } catch (PcapNativeException e) {
            lastDeviceListError = buildDeviceListMessage(e);
            return null;
        }
    }

    public static String getLastDeviceListError() {
        return lastDeviceListError;
    }

    public static JpcapCaptor openDevice(NetworkInterface device, int snaplen, boolean promisc, int timeout)
            throws IOException {
        try {
            PcapHandle handle = device.getDelegate().openLive(
                    snaplen,
                    promisc ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
                            : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS,
                    timeout
            );
            return new JpcapCaptor(handle);
        } catch (PcapNativeException e) {
            throw new IOException(buildOpenDeviceMessage(device, promisc, e), e);
        } catch (UnsatisfiedLinkError e) {
            throw new IOException(buildNativeLoadMessage(e), e);
        }
    }

    public static JpcapCaptor openFile(String path) throws IOException {
        try {
            return new JpcapCaptor(Pcaps.openOffline(path));
        } catch (PcapNativeException e) {
            throw new IOException("Failed to open capture file: " + path, e);
        }
    }

    public int processPacket(int count, PacketReceiver receiver) {
        int processed = 0;
        breakRequested = false;

        while (processed < count && !breakRequested) {
            try {
                org.pcap4j.packet.Packet delegate = handle.getNextPacketEx();
                Timestamp timestamp = handle.getTimestamp();
                Packet packet = PacketFactory.create(delegate, timestamp);
                receiver.receivePacket(packet);
                processed++;
            } catch (TimeoutException e) {
                break;
            } catch (EOFException e) {
                break;
            } catch (PcapNativeException e) {
                break;
            } catch (NotOpenException e) {
                break;
            }
        }

        return processed;
    }

    public void breakLoop() {
        breakRequested = true;
    }

    public void close() {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }

    PcapDumper dumpOpen(String path) throws PcapNativeException, NotOpenException {
        return handle.dumpOpen(path);
    }

    public PcapHandle getHandle() {
        return handle;
    }

    private static String buildDeviceListMessage(PcapNativeException e) {
        StringBuilder message = new StringBuilder("Failed to enumerate capture devices.");
        appendCause(message, e);
        appendMacPermissionHint(message);
        return message.toString();
    }

    private static String buildOpenDeviceMessage(NetworkInterface device, boolean promisc, Exception e) {
        StringBuilder message = new StringBuilder("Failed to open capture device");
        if (device != null) {
            message.append(" '").append(device.name).append("'");
        }
        message.append(promisc ? " in promiscuous mode." : ".");
        appendCause(message, e);
        appendMacPermissionHint(message);
        return message.toString();
    }

    private static String buildNativeLoadMessage(UnsatisfiedLinkError e) {
        StringBuilder message = new StringBuilder("Failed to load the native packet capture library.");
        appendCause(message, e);
        if (isMac()) {
            message.append(" On Apple Silicon, make sure Maven resolved an arm64-compatible JNA and that libpcap is installed.");
        }
        return message.toString();
    }

    private static void appendCause(StringBuilder message, Throwable error) {
        String causeMessage = error.getMessage();
        if (causeMessage != null && causeMessage.length() > 0) {
            message.append(" Cause: ").append(causeMessage);
        }
    }

    private static void appendMacPermissionHint(StringBuilder message) {
        if (isMac()) {
            message.append(" On macOS this is often a /dev/bpf permission issue. Try running the app with elevated privileges, for example `make run-sudo`.");
        }
    }

    private static boolean isMac() {
        return System.getProperty("os.name", "").toLowerCase().contains("mac");
    }
}
