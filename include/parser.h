#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>
#include <string>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// Structure to hold parsed packet information
struct PacketInfo {
    std::string timestamp;
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    std::string protocol;
    size_t packetSize;
};

class Parser {
public:
    Parser();
    ~Parser();

    // Parse a raw packet and extract information
    PacketInfo parsePacket(const u_char* packet, const struct pcap_pkthdr* header);

private:
    // Helper methods for parsing specific protocol headers
    void parseEthernetHeader(const u_char* packet, PacketInfo& info);
    void parseIPHeader(const u_char* packet, PacketInfo& info);
    void parseTCPHeader(const u_char* packet, const struct ip* ipHeader, PacketInfo& info);
    void parseUDPHeader(const u_char* packet, const struct ip* ipHeader, PacketInfo& info);
};

#endif // PARSER_H
