#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <string>
#include <functional>
#include <vector>

class Sniffer {
public:
    Sniffer();
    ~Sniffer();

    // Initialize the sniffer with a specific interface
    bool init(const std::string& interface);
    
    // Start capturing packets with a callback function
    bool startSniffing(std::function<void(const u_char*, const struct pcap_pkthdr*)> callback, volatile sig_atomic_t& externalRunning);
    
    // Stop the packet capture
    void stopSniffing();
    
    // Get a list of available network interfaces
    static std::vector<std::string> getInterfaces();

private:
    pcap_t* handle;
    bool running;
    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif // SNIFFER_H
