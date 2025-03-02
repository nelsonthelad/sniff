#include "sniffer.h"
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <csignal>

Sniffer::Sniffer() : handle(nullptr), running(false) {
    // Initialize errbuf
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
}

Sniffer::~Sniffer() {
    stopSniffing();
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
}

bool Sniffer::init(const std::string& interface) {
    // Close any existing handle
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }

    // Open the device for sniffing
    handle = pcap_open_live(
        interface.c_str(),  // device name
        BUFSIZ,             // snapshot length
        1,                  // promiscuous mode
        100,                // read timeout (ms) - reduced for better responsiveness
        errbuf              // error buffer
    );

    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return false;
    }

    // Check if the device provides Ethernet headers
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Device " << interface << " doesn't provide Ethernet headers" << std::endl;
        pcap_close(handle);
        handle = nullptr;
        return false;
    }

    return true;
}

bool Sniffer::startSniffing(std::function<void(const u_char*, const struct pcap_pkthdr*)> callback, volatile sig_atomic_t& externalRunning) {
    if (!handle) {
        std::cerr << "Sniffer not initialized" << std::endl;
        return false;
    }

    if (running) {
        std::cerr << "Sniffer already running" << std::endl;
        return false;
    }

    running = true;
    std::cout << "Packet capture started. Press Ctrl+C to stop." << std::endl;

    // Start packet capture loop
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (running && externalRunning) {
        // Check the external running flag first
        if (!externalRunning) {
            std::cout << "External stop signal received." << std::endl;
            break;
        }

        // Use pcap_next_ex with a short timeout
        int res = pcap_next_ex(handle, &header, &packet);
        
        // Check for errors or timeout
        if (res == 0) {
            // Timeout elapsed without receiving a packet
            continue;
        } else if (res == -1) {
            // Error occurred
            std::cerr << "Error reading packet: " << pcap_geterr(handle) << std::endl;
            break;
        } else if (res == -2) {
            // End of pcap file (not applicable for live capture)
            break;
        }
        
        // Process the packet if we got one
        if (packet && running && externalRunning) {
            callback(packet, header);
        }
        
        // Check again if we should continue running
        if (!externalRunning) {
            std::cout << "External stop signal received during processing." << std::endl;
            break;
        }
    }

    std::cout << "Packet capture loop exited" << std::endl;
    running = false;
    return true;
}

void Sniffer::stopSniffing() {
    running = false;
    std::cout << "Stopping sniffer..." << std::endl;
}

std::vector<std::string> Sniffer::getInterfaces() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return interfaces;
    }
    
    // Add all interfaces to the vector
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        interfaces.push_back(dev->name);
    }
    
    // Free the device list
    pcap_freealldevs(alldevs);
    
    return interfaces;
}
