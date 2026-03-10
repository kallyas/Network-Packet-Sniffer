# Network Packet Sniffer

Java desktop packet sniffer and protocol analyzer with a Swing UI, live capture, offline file loading, protocol statistics, packet detail inspection, filtering, and sortable packet tables.

![Application screenshot](media/Screenshot%202026-03-09%20at%2021.46.30.png)

## Current state

This project originally depended on the obsolete Jpcap runtime. It has now been migrated to a maintained backend based on Pcap4J.

- Capture backend: `org.pcap4j:pcap4j-core:1.8.2`
- Build system: Maven
- Legacy app-facing API preserved through a compatibility layer in `src/main/java/jpcap/`

## Features

- Live packet capture from a selected network interface
- Offline packet loading from capture files
- Packet saving to dump files
- Protocol analyzers for Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, HTTP, FTP, Telnet, SSH, SMTP, and POP3
- Sortable packet table
- Live table filtering
- Packet detail tree and raw packet byte view
- Cumulative and continuous statistics windows
- Bounded in-memory packet buffer with live status metrics

## Requirements

- Java 17 or newer
- Maven 3.9+
- Native packet capture library

Platform requirements:

- macOS / Linux: `libpcap`
- Windows: `Npcap`

## Install

### macOS

```bash
brew install maven libpcap
```

`libpcap` is keg-only on Homebrew. If runtime linking ever fails, export:

```bash
export LDFLAGS="-L/opt/homebrew/opt/libpcap/lib"
export CPPFLAGS="-I/opt/homebrew/opt/libpcap/include"
export PKG_CONFIG_PATH="/opt/homebrew/opt/libpcap/lib/pkgconfig"
```

## Build

```bash
mvn compile
```

Build a distributable fat jar:

```bash
mvn package -DskipTests
```

## Run

> Warning
> Live packet capture requires elevated permissions. Run the app with `sudo` on macOS/Linux, or from an Administrator shell on Windows, if you want to capture traffic from a network interface.

```bash
mvn exec:java
```

Run the packaged fat jar:

```bash
java -jar target/network-packet-sniffer-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## Project structure

- `src/main/java/app/` application startup, capture flow, loader classes
- `src/main/java/analyzer/` protocol analyzers
- `src/main/java/stat/` statistics calculators
- `src/main/java/ui/` Swing UI
- `src/main/java/jpcap/` compatibility layer backed by Pcap4J
- `src/main/resources/image/` application icons
- `src/test/java/` automated tests

## Notes

- The UI and analyzers still use the historical `jpcap.*` packet model internally, but that API is now implemented locally on top of Pcap4J.
- Live capture availability depends on OS permissions and native packet capture support.
- Offline analysis and most UI functionality do not require elevated privileges once a capture file is available.
