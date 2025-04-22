#ifndef WIREGUARD_MANAGER_H
#define WIREGUARD_MANAGER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>

/**
 * WireGuard VPN server manager
 */
class WireGuardManager {
public:
    struct ServerInfo {
        std::string name;
        std::string location;
        std::string ipAddress;
        unsigned int port;
        std::string publicKey;
        std::string privateKey;
        unsigned long bandwidth;
        unsigned long usedBandwidth;
        std::string status; // "active", "maintenance", "offline"
        bool premiumOnly;
    };
    
    struct ClientConfig {
        std::string interface;
        std::string privateKey;
        std::string address;
        std::string dns;
        std::string publicKey;
        std::string endpoint;
        std::string allowedIPs;
        int keepalive;
    };
    
    // Constructor
    WireGuardManager();
    
    // Add a server
    bool addServer(const ServerInfo& serverInfo);
    
    // Remove a server
    bool removeServer(const std::string& serverName);
    
    // Get server info
    bool getServerInfo(const std::string& serverName, ServerInfo& info);
    
    // Get all servers
    std::vector<ServerInfo> getAllServers();
    
    // Get premium-only servers
    std::vector<ServerInfo> getPremiumServers();
    
    // Get free servers
    std::vector<ServerInfo> getFreeServers();
    
    // Update server status
    bool updateServerStatus(const std::string& serverName, const std::string& status);
    
    // Generate client configuration
    bool generateClientConfig(
        const std::string& serverName, const std::string& clientName, 
        bool isPremium, ClientConfig& config);
    
    // Apply server configuration to the system
    bool applyServerConfig(const std::string& serverName);
    
    // Update bandwidth usage
    bool updateBandwidthUsage(const std::string& serverName, unsigned long bytesUsed);

private:
    // Generate WireGuard keys
    static void generateKeyPair(std::string& privateKey, std::string& publicKey);
    
    // Run a system command and get output
    static std::string runCommand(const std::string& command);
    
    std::unordered_map<std::string, ServerInfo> servers_;
    std::mutex serversMutex_;
};

#endif // WIREGUARD_MANAGER_H
