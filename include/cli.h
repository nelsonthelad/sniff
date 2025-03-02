#ifndef CLI_H
#define CLI_H

#include <string>
#include <vector>
#include <functional>
#include "sniffer.h"
#include "parser.h"

struct SnifferConfig {
    std::string interface;
    std::string logFilePath;
    bool filterTCP;
    bool filterUDP;
    bool filterICMP;
    bool filterOther;
};

class CLI {
public:
    CLI();
    ~CLI();

    // Display the main menu and get user input
    SnifferConfig showMenu();
    
    // Display available network interfaces
    void showInterfaces(const std::vector<std::string>& interfaces);
    
    // Display packet information in real-time
    void displayPacket(const PacketInfo& packetInfo);
    
    // Display help information
    void showHelp();

private:
    // Helper methods for user input
    std::string getInput(const std::string& prompt);
    int getIntInput(const std::string& prompt, int min, int max);
    bool getBoolInput(const std::string& prompt);
};

#endif // CLI_H
