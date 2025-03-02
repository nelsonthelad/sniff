#include "sniffer.h"
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>

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
        1000,               // read timeout (ms)
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

bool Sniffer::startSniffing(std::function<void(const u_char*, const struct pcap_pkthdr*)> callback) {
    if (!handle) {
        std::cerr << "Sniffer not initialized" << std::endl;
        return false;
    }

    if (running) {
        std::cerr << "Sniffer already running" << std::endl;
        return false;
    }

    running = true;

    // Start packet capture loop
    struct pcap_pkthdr header;
    const u_char* packet;

    while (running) {
        packet = pcap_next(handle, &header);
        if (packet) {
            callback(packet, &header);
        }
        // Small delay to prevent CPU hogging
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return true;
}

void Sniffer::stopSniffing() {
    running = false;
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
