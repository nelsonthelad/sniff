#include "cli.h"
#include "parser.h"
#include <iostream>
#include <limits>
#include <iomanip>

CLI::CLI() {
    // Nothing to initialize
}

CLI::~CLI() {
    // Nothing to clean up
}

SnifferConfig CLI::showMenu() {
    SnifferConfig config;
    
    std::cout << "\n===== Packet Sniffer Configuration =====\n" << std::endl;
    
    // Get network interface
    std::vector<std::string> interfaces = Sniffer::getInterfaces();
    showInterfaces(interfaces);
    
    int interfaceIndex = getIntInput("Select interface (1-" + std::to_string(interfaces.size()) + "): ", 1, interfaces.size());
    config.interface = interfaces[interfaceIndex - 1];
    
    // Get log file path
    config.logFilePath = getInput("Enter log file path (default: sniff_log.csv): ");
    if (config.logFilePath.empty()) {
        config.logFilePath = "sniff_log.csv";
    }
    
    // Configure filters
    std::cout << "\n----- Protocol Filters -----" << std::endl;
    config.filterTCP = getBoolInput("Capture TCP packets? (y/n): ");
    config.filterUDP = getBoolInput("Capture UDP packets? (y/n): ");
    config.filterICMP = getBoolInput("Capture ICMP packets? (y/n): ");
    config.filterOther = getBoolInput("Capture other IP packets? (y/n): ");
    
    // Summary
    std::cout << "\n----- Configuration Summary -----" << std::endl;
    std::cout << "Interface: " << config.interface << std::endl;
    std::cout << "Log File: " << config.logFilePath << std::endl;
    std::cout << "Filters: ";
    std::cout << (config.filterTCP ? "TCP " : "");
    std::cout << (config.filterUDP ? "UDP " : "");
    std::cout << (config.filterICMP ? "ICMP " : "");
    std::cout << (config.filterOther ? "Other " : "");
    std::cout << std::endl;
    
    std::cout << "\nPress Enter to start sniffing..." << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    return config;
}

void CLI::showInterfaces(const std::vector<std::string>& interfaces) {
    std::cout << "----- Available Network Interfaces -----" << std::endl;
    
    if (interfaces.empty()) {
        std::cout << "No interfaces found!" << std::endl;
        return;
    }
    
    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << (i + 1) << ". " << interfaces[i] << std::endl;
    }
    
    std::cout << std::endl;
}

void CLI::displayPacket(const PacketInfo& packetInfo) {
    std::cout << "Time: " << packetInfo.timestamp
              << " | " << packetInfo.sourceIP << ":" << packetInfo.sourcePort
              << " -> " << packetInfo.destIP << ":" << packetInfo.destPort
              << " | " << packetInfo.protocol
              << " | Size: " << packetInfo.packetSize << " bytes" << std::endl;
}

void CLI::showHelp() {
    std::cout << "\n===== Packet Sniffer Help =====\n" << std::endl;
    std::cout << "This program captures and analyzes network packets on a specified interface." << std::endl;
    std::cout << "It can filter packets by protocol type and log the results to a CSV file." << std::endl;
    std::cout << "\nUsage:" << std::endl;
    std::cout << "  1. Select a network interface from the list" << std::endl;
    std::cout << "  2. Specify a log file path (or use the default)" << std::endl;
    std::cout << "  3. Configure protocol filters" << std::endl;
    std::cout << "  4. Press Enter to start sniffing" << std::endl;
    std::cout << "  5. Press Ctrl+C to stop sniffing" << std::endl;
    std::cout << "\nNote: This program requires root/administrator privileges to capture packets." << std::endl;
}

std::string CLI::getInput(const std::string& prompt) {
    std::string input;
    std::cout << prompt;
    std::getline(std::cin, input);
    return input;
}

int CLI::getIntInput(const std::string& prompt, int min, int max) {
    int input;
    while (true) {
        std::cout << prompt;
        if (std::cin >> input) {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            if (input >= min && input <= max) {
                return input;
            }
        } else {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
        std::cout << "Invalid input. Please enter a number between " << min << " and " << max << "." << std::endl;
    }
}

bool CLI::getBoolInput(const std::string& prompt) {
    while (true) {
        std::string input = getInput(prompt);
        if (input == "y" || input == "Y" || input == "yes" || input == "Yes") {
            return true;
        } else if (input == "n" || input == "N" || input == "no" || input == "No") {
            return false;
        }
        std::cout << "Invalid input. Please enter 'y' or 'n'." << std::endl;
    }
}
