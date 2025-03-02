# Sniff

A simple terminal-based packet sniffer for capturing and analyzing network traffic.

## Features

- Capture packets on any network interface
- Parse Ethernet, IP, TCP, UDP, and ICMP headers
- Filter packets by protocol type
- Display packet information in real-time
- Log packet details to a CSV file

## Requirements

- C++17 compatible compiler
- libpcap development library

## Installation

### Install Dependencies

#### On Debian/Ubuntu:
```bash
sudo apt-get install libpcap-dev
```

#### On macOS:
```bash
brew install libpcap
```

### Build the Project

```bash
git clone https://github.com/nelsonthelad/sniff.git
cd sniff
make
```

## Usage

The packet sniffer requires root/administrator privileges to capture packets:

```bash
sudo ./sniff
```

Follow the on-screen prompts to:
1. Select a network interface
2. Specify a log file path
3. Configure protocol filters
4. Start packet capture

Press `Ctrl+C` to stop the packet capture.

## Log File Format

The packet sniffer logs captured packets to a CSV file with the following columns:
- Timestamp
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Packet Size (bytes)

## Disclaimer

This tool is intended for educational purposes and network troubleshooting. Only use it on networks you have permission to monitor. Unauthorized packet sniffing may be illegal in your jurisdiction.
