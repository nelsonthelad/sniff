#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include "parser.h"

class Logger {
public:
    Logger();
    ~Logger();

    // Initialize the logger with a log file path
    bool init(const std::string& logFilePath);
    
    // Log a packet's information
    bool logPacket(const PacketInfo& packetInfo);
    
    // Close the log file
    void close();

private:
    std::ofstream logFile;
    std::mutex logMutex;
    bool isInitialized;
};

#endif // LOGGER_H
