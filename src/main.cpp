#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include "sniffer.h"
#include "parser.h"
#include "logger.h"
#include "cli.h"

// Global variables for signal handling
volatile sig_atomic_t running = true;

// Signal handler for graceful termination
void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ". Stopping packet capture..." << std::endl;
    running = false;
}

int main() {
    // Display the ASCII art banner
    std::cout << R"(
+-----------------------------+
|                 _ ________  |
|     _________  (_) __/ __/  |
|    / ___/ __ \/ / /_/ /_    |
|   (__  ) / / / / __/ __/    |
|  /____/_/ /_/_/_/ /_/       |
|                             |
+-----------------------------+ 
   )" << std::endl;
    
    std::cout << "Packet Sniffer v1.0" << std::endl;
    std::cout << "A simple network packet capture and analysis tool" << std::endl;
    
    // Register signal handler for Ctrl+C
    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    // Initialize components
    CLI cli;
    Sniffer sniffer;
    Parser parser;
    Logger logger;
    
    // Get configuration from user
    SnifferConfig config = cli.showMenu();
    
    // Initialize logger
    if (!logger.init(config.logFilePath)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }
    
    // Initialize sniffer
    if (!sniffer.init(config.interface)) {
        std::cerr << "Failed to initialize sniffer" << std::endl;
        return 1;
    }
    
    std::cout << "Starting packet capture on interface " << config.interface << "..." << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    
    // Create a separate thread for packet sniffing
    std::thread snifferThread([&]() {
        sniffer.startSniffing([&](const u_char* packet, const struct pcap_pkthdr* header) {
            // Parse the packet
            PacketInfo info = parser.parsePacket(packet, header);
            
            // Apply filters
            bool shouldProcess = false;
            if (info.protocol == "TCP" && config.filterTCP) shouldProcess = true;
            else if (info.protocol == "UDP" && config.filterUDP) shouldProcess = true;
            else if (info.protocol == "ICMP" && config.filterICMP) shouldProcess = true;
            else if ((info.protocol == "Other IP" || info.protocol == "Non-IP") && config.filterOther) shouldProcess = true;
            
            if (shouldProcess) {
                // Display packet information
                cli.displayPacket(info);
                
                // Log packet information
                logger.logPacket(info);
            }
            
            // Return true to continue, false to stop
            return running;
        }, running);
    });
    
    // Main thread monitors the running flag
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Signal the sniffer to stop
    sniffer.stopSniffing();
    
    // Wait for the sniffer thread to finish
    std::cout << "Waiting for sniffer thread to finish..." << std::endl;
    if (snifferThread.joinable()) {
        snifferThread.join();
    }
    
    std::cout << "Packet capture stopped" << std::endl;
    
    return 0;
}