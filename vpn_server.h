#ifndef VPN_SERVER_H
#define VPN_SERVER_H

#include <asio.hpp>
#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <functional>

/**
 * VPN Server class using ASIO for networking
 * Handles client connections, authentication, and data routing
 */
class VpnServer {
public:
    struct ClientConnection {
        std::string username;
        bool isPremium;
        std::string assignedIp;
        asio::ip::tcp::socket socket;
        uint64_t bytesTransferred;
        std::chrono::system_clock::time_point connectTime;
        
        ClientConnection(asio::ip::tcp::socket&& s);
    };
    
    // Constructor
    VpnServer(unsigned short port);
    
    // Destructor
    ~VpnServer();
    
    // Start the server
    void start();
    
    // Stop the server
    void stop();
    
    // Get server status
    bool isRunning() const;
    
    // Get connection statistics
    struct ServerStats {
        unsigned int activeConnections;
        unsigned int totalConnections;
        uint64_t totalBytesTransferred;
    };
    
    ServerStats getStats() const;
    
    // Set authentication handler
    using AuthHandler = std::function<bool(const std::string& token, std::string& username, bool& isPremium)>;
    void setAuthHandler(AuthHandler handler);
    
    // Set bandwidth limit handler
    using BandwidthLimitHandler = std::function<uint64_t(const std::string& username, bool isPremium)>;
    void setBandwidthLimitHandler(BandwidthLimitHandler handler);

private:
    void acceptConnection();
    void handleAuthentication(std::shared_ptr<ClientConnection> client);
    void handleData(std::shared_ptr<ClientConnection> client);
    void removeClient(std::shared_ptr<ClientConnection> client);
    
    asio::io_context io_context_;
    asio::ip::tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<ClientConnection>> clients_;
    std::mutex clientsMutex_;
    std::atomic<bool> running_;
    
    ServerStats stats_;
    std::mutex statsMutex_;
    
    AuthHandler authHandler_;
    BandwidthLimitHandler bandwidthLimitHandler_;
};

#endif // VPN_SERVER_H
