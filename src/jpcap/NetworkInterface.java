package jpcap;

import org.pcap4j.core.PcapNetworkInterface;

public class NetworkInterface {
    public final String name;
    public final String description;

    private final PcapNetworkInterface delegate;

    NetworkInterface(PcapNetworkInterface delegate) {
        this.delegate = delegate;
        this.name = delegate.getName();
        this.description = delegate.getDescription();
    }

    PcapNetworkInterface getDelegate() {
        return delegate;
    }
}
