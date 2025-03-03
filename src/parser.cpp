#include "parser.h"
#include <ctime>
#include <iomanip>
#include <sstream>

Parser::Parser() {
    // Nothing to initialize
}

Parser::~Parser() {
    // Nothing to clean up
}

PacketInfo Parser::parsePacket(const u_char* packet, const struct pcap_pkthdr* header) {
    PacketInfo info;
    
    // Set timestamp
    std::time_t timestamp = header->ts.tv_sec;
    std::tm* timeInfo = std::localtime(&timestamp);
    std::stringstream ss;
    ss << std::put_time(timeInfo, "%Y-%m-%d %H:%M:%S");
    info.timestamp = ss.str();
    
    // Set packet size
    info.packetSize = header->len;
    
    // Initialize default values
    info.sourceIP = "Unknown";
    info.destIP = "Unknown";
    info.sourcePort = 0;
    info.destPort = 0;
    info.protocol = "Unknown";
    
    // Parse Ethernet header
    parseEthernetHeader(packet, info);
    
    return info;
}

void Parser::parseEthernetHeader(const u_char* packet, PacketInfo& info) {
    const struct ether_header* ethernetHeader = reinterpret_cast<const struct ether_header*>(packet);
    
    // Check if it's an IP packet
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        // Parse IP header (Ethernet header is typically 14 bytes)
        parseIPHeader(packet + sizeof(struct ether_header), info);
    } else {
        info.protocol = "Non-IP";
    }
}

void Parser::parseIPHeader(const u_char* packet, PacketInfo& info) {
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet);
    
    // Extract source and destination IP addresses
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
    
    info.sourceIP = sourceIP;
    info.destIP = destIP;
    
    // Determine the protocol
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP:
            info.protocol = "TCP";
            parseTCPHeader(packet + (ipHeader->ip_hl * 4), ipHeader, info);
            break;
        case IPPROTO_UDP:
            info.protocol = "UDP";
            parseUDPHeader(packet + (ipHeader->ip_hl * 4), ipHeader, info);
            break;
        case IPPROTO_ICMP:
            info.protocol = "ICMP";
            break;
        default:
            info.protocol = "Other IP";
            break;
    }
}

void Parser::parseTCPHeader(const u_char* packet, const struct ip* ipHeader, PacketInfo& info) {
    const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(packet);
    
    // Extract source and destination ports
    info.sourcePort = ntohs(tcpHeader->th_sport);
    info.destPort = ntohs(tcpHeader->th_dport);
}

void Parser::parseUDPHeader(const u_char* packet, const struct ip* ipHeader, PacketInfo& info) {
    const struct udphdr* udpHeader = reinterpret_cast<const struct udphdr*>(packet);
    
    // Extract source and destination ports
    info.sourcePort = ntohs(udpHeader->uh_sport);
    info.destPort = ntohs(udpHeader->uh_dport);
}
