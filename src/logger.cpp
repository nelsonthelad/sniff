#include "logger.h"
#include <iostream>
#include <iomanip>

Logger::Logger() : isInitialized(false) {
    // Nothing else to initialize
}

Logger::~Logger() {
    close();
}

bool Logger::init(const std::string& logFilePath) {
    // Lock to prevent concurrent access
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Close any existing log file
    if (logFile.is_open()) {
        logFile.close();
    }
    
    // Open the log file
    logFile.open(logFilePath, std::ios::out | std::ios::app);
    
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file: " << logFilePath << std::endl;
        return false;
    }
    
    // Write header if the file is new (empty)
    if (logFile.tellp() == 0) {
        logFile << "Timestamp,Source IP,Destination IP,Source Port,Destination Port,Protocol,Packet Size (bytes)" << std::endl;
    }
    
    isInitialized = true;
    return true;
}

bool Logger::logPacket(const PacketInfo& packetInfo) {
    // Lock to prevent concurrent access
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (!isInitialized || !logFile.is_open()) {
        std::cerr << "Logger not initialized" << std::endl;
        return false;
    }
    
    // Write packet information to the log file in CSV format
    logFile << packetInfo.timestamp << ","
            << packetInfo.sourceIP << ","
            << packetInfo.destIP << ","
            << packetInfo.sourcePort << ","
            << packetInfo.destPort << ","
            << packetInfo.protocol << ","
            << packetInfo.packetSize << std::endl;
    
    // Flush to ensure data is written immediately
    logFile.flush();
    
    return true;
}

void Logger::close() {
    // Lock to prevent concurrent access
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile.close();
    }
    
    isInitialized = false;
}
