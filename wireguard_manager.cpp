#include "wireguard_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <cstdlib>
#include <array>
#include <memory>

WireGuardManager::WireGuardManager() {
    // Initialize with default servers
    ServerInfo usServer;
    usServer.name = "US-Free";
    usServer.location = "New York";
    usServer.ipAddress = "10.0.0.1";
    usServer.port = 51820;
    generateKeyPair(usServer.privateKey, usServer.publicKey);
    usServer.bandwidth = 5000; // 5GB
    usServer.usedBandwidth = 0;
    usServer.status = "active";
    usServer.premiumOnly = false;
    
    ServerInfo euServer;
    euServer.name = "EU-Free";
    euServer.location = "Amsterdam";
    euServer.ipAddress = "10.0.0.2";
    euServer.port = 51820;
    generateKeyPair(euServer.privateKey, euServer.publicKey);
    euServer.bandwidth = 5000; // 5GB
    euServer.usedBandwidth = 0;
    euServer.status = "active";
    euServer.premiumOnly = false;
    
    ServerInfo usPremiumServer;
    usPremiumServer.name = "US-Premium";
    usPremiumServer.location = "Los Angeles";
    usPremiumServer.ipAddress = "10.0.0.3";
    usPremiumServer.port = 51820;
    generateKeyPair(usPremiumServer.privateKey, usPremiumServer.publicKey);
    usPremiumServer.bandwidth = 100000; // 100GB
    usPremiumServer.usedBandwidth = 0;
    usPremiumServer.status = "active";
    usPremiumServer.premiumOnly = true;
    
    ServerInfo euPremiumServer;
    euPremiumServer.name = "EU-Premium";
    euPremiumServer.location = "London";
    euPremiumServer.ipAddress = "10.0.0.4";
    euPremiumServer.port = 51820;
    generateKeyPair(euPremiumServer.privateKey, euPremiumServer.publicKey);
    euPremiumServer.bandwidth = 100000; // 100GB
    euPremiumServer.usedBandwidth = 0;
    euPremiumServer.status = "active";
    euPremiumServer.premiumOnly = true;
    
    // Add servers to map
    servers_[usServer.name] = usServer;
    servers_[euServer.name] = euServer;
    servers_[usPremiumServer.name] = usPremiumServer;
    servers_[euPremiumServer.name] = euPremiumServer;
    
    std::cout << "WireGuard Manager initialized with " << servers_.size() << " servers" << std::endl;
}

bool WireGuardManager::addServer(const ServerInfo& serverInfo) {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    // Check if server with this name already exists
    if (servers_.find(serverInfo.name) != servers_.end()) {
        return false;
    }
    
    servers_[serverInfo.name] = serverInfo;
    return true;
}

bool WireGuardManager::removeServer(const std::string& serverName) {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    auto it = servers_.find(serverName);
    if (it == servers_.end()) {
        return false;
    }
    
    servers_.erase(it);
    return true;
}

bool WireGuardManager::getServerInfo(const std::string& serverName, ServerInfo& info) {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    auto it = servers_.find(serverName);
    if (it == servers_.end()) {
        return false;
    }
    
    info = it->second;
    return true;
}

std::vector<WireGuardManager::ServerInfo> WireGuardManager::getAllServers() {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    std::vector<ServerInfo> result;
    for (const auto& pair : servers_) {
        result.push_back(pair.second);
    }
    
    return result;
}

std::vector<WireGuardManager::ServerInfo> WireGuardManager::getPremiumServers() {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    std::vector<ServerInfo> result;
    for (const auto& pair : servers_) {
        if (pair.second.premiumOnly && pair.second.status == "active") {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

std::vector<WireGuardManager::ServerInfo> WireGuardManager::getFreeServers() {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    std::vector<ServerInfo> result;
    for (const auto& pair : servers_) {
        if (!pair.second.premiumOnly && pair.second.status == "active") {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

bool WireGuardManager::updateServerStatus(const std::string& serverName, const std::string& status) {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    auto it = servers_.find(serverName);
    if (it == servers_.end()) {
        return false;
    }
    
    it->second.status = status;
    return true;
}

bool WireGuardManager::generateClientConfig(
    const std::string& serverName, const std::string& clientName, 
    bool isPremium, ClientConfig& config) {
    
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    auto it = servers_.find(serverName);
    if (it == servers_.end()) {
        return false;
    }
    
    // Check if this is a premium-only server and user is not premium
    if (it->second.premiumOnly && !isPremium) {
        return false;
    }
    
    // Generate client keys
    std::string privateKey, publicKey;
    generateKeyPair(privateKey, publicKey);
    
    // Create client IP address (10.0.0.x where x is random between 10 and 250)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10, 250);
    std::string clientIP = "10.0.0." + std::to_string(dis(gen));
    
    // Fill in config
    config.interface = "[Interface]";
    config.privateKey = "PrivateKey = " + privateKey;
    config.address = "Address = " + clientIP + "/24";
    config.dns = "DNS = 1.1.1.1, 8.8.8.8";
    
    config.publicKey = "PublicKey = " + it->second.publicKey;
    config.endpoint = "Endpoint = " + it->second.ipAddress + ":" + std::to_string(it->second.port);
    config.allowedIPs = "AllowedIPs = 0.0.0.0/0, ::/0";
    config.keepalive = 25;
    
    std::cout << "Generated client config for " << clientName << " on server " << serverName << std::endl;
    
    return true;
}

bool WireGuardManager::applyServerConfig(const std::string& serverName) {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    auto it = servers_.find(serverName);
    if (it == servers_.end()) {
        return false;
    }
    
    // Create WireGuard configuration file
    std::string configPath = "/etc/wireguard/" + serverName + ".conf";
    std::ofstream configFile(configPath);
    
    if (!configFile.is_open()) {
        std::cerr << "Failed to open config file: " << configPath << std::endl;
        return false;
    }
    
    // Write server configuration
    configFile << "[Interface]\n";
    configFile << "Address = " << it->second.ipAddress << "/24\n";
    configFile << "ListenPort = " << it->second.port << "\n";
    configFile << "PrivateKey = " << it->second.privateKey << "\n";
    configFile << "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n";
    configFile << "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n";
    
    configFile.close();
    
    // Apply configuration
    std::string command = "wg-quick up " + serverName;
    std::string output = runCommand(command);
    
    if (output.find("error") != std::string::npos) {
        std::cerr << "Failed to apply WireGuard config: " << output << std::endl;
        return false;
    }
    
    std::cout << "Applied WireGuard config for server " << serverName << std::endl;
    return true;
}

bool WireGuardManager::updateBandwidthUsage(const std::string& serverName, unsigned long bytesUsed) {
    std::lock_guard<std::mutex> lock(serversMutex_);
    
    auto it = servers_.find(serverName);
    if (it == servers_.end()) {
        return false;
    }
    
    it->second.usedBandwidth += bytesUsed / (1024 * 1024); // Convert bytes to MB
    return true;
}

void WireGuardManager::generateKeyPair(std::string& privateKey, std::string& publicKey) {
    // In a real implementation, this would call the WireGuard tools
    // For demonstration, we'll generate some random strings
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    // Generate 32-byte private key
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    privateKey = ss.str();
    
    // In reality, the public key would be derived from the private key
    // For demonstration, we'll generate another random string
    ss.str("");
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    publicKey = ss.str();
}

std::string WireGuardManager::runCommand(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;
    
    // Create a process to execute the command
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        return "Error executing command";
    }
    
    // Read the output
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}
