#include "vpn_server.h"
#include <iostream>
#include <chrono>

VpnServer::ClientConnection::ClientConnection(asio::ip::tcp::socket&& s)
    : socket(std::move(s)), bytesTransferred(0), 
      connectTime(std::chrono::system_clock::now()), isPremium(false) {}

VpnServer::VpnServer(unsigned short port)
    : acceptor_(io_context_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
      running_(false) {
    
    stats_.activeConnections = 0;
    stats_.totalConnections = 0;
    stats_.totalBytesTransferred = 0;
    
    // Set default auth handler (always deny)
    authHandler_ = [](const std::string&, std::string&, bool&) { return false; };
    
    // Set default bandwidth handler (10MB for free, 100MB for premium)
    bandwidthLimitHandler_ = [](const std::string&, bool isPremium) {
        return isPremium ? 104857600 : 10485760; // 100MB vs 10MB in bytes
    };
}

VpnServer::~VpnServer() {
    stop();
}

void VpnServer::start() {
    if (running_) {
        return;
    }
    
    running_ = true;
    acceptConnection();
    
    // Start the ASIO io_context in a separate thread
    std::thread([this]() {
        io_context_.run();
    }).detach();
    
    std::cout << "VPN Server started" << std::endl;
}

void VpnServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    io_context_.stop();
    
    // Close all client connections
    std::lock_guard<std::mutex> lock(clientsMutex_);
    for (auto& client : clients_) {
        if (client->socket.is_open()) {
            asio::error_code ec;
            client->socket.close(ec);
        }
    }
    clients_.clear();
    
    std::cout << "VPN Server stopped" << std::endl;
}

bool VpnServer::isRunning() const {
    return running_;
}

VpnServer::ServerStats VpnServer::getStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void VpnServer::setAuthHandler(AuthHandler handler) {
    authHandler_ = handler;
}

void VpnServer::setBandwidthLimitHandler(BandwidthLimitHandler handler) {
    bandwidthLimitHandler_ = handler;
}

void VpnServer::acceptConnection() {
    acceptor_.async_accept(
        [this](asio::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                std::cout << "New connection from " << socket.remote_endpoint() << std::endl;
                
                // Create new client connection
                auto client = std::make_shared<ClientConnection>(std::move(socket));
                
                // Update stats
                {
                    std::lock_guard<std::mutex> lock(statsMutex_);
                    stats_.activeConnections++;
                    stats_.totalConnections++;
                }
                
                // Add to clients list
                {
                    std::lock_guard<std::mutex> lock(clientsMutex_);
                    clients_.push_back(client);
                }
                
                // Start authentication process
                handleAuthentication(client);
            }
            
            // Accept next connection
            if (running_) {
                acceptConnection();
            }
        }
    );
}

void VpnServer::handleAuthentication(std::shared_ptr<ClientConnection> client) {
    auto authBuffer = std::make_shared<std::array<char, 1024>>();
    
    asio::async_read_until(
        client->socket,
        asio::dynamic_buffer(*authBuffer),
        '\n',
        [this, client, authBuffer](asio::error_code ec, std::size_t length) {
            if (ec) {
                removeClient(client);
                return;
            }
            
            std::string authToken(authBuffer->data(), length - 1); // Remove the \n
            std::string username;
            bool isPremium = false;
            
            // Call auth handler to verify the token
            bool authenticated = authHandler_(authToken, username, isPremium);
            
            if (authenticated) {
                client->username = username;
                client->isPremium = isPremium;
                
                // Send success response
                std::string response = "AUTH_SUCCESS\n";
                asio::async_write(
                    client->socket,
                    asio::buffer(response),
                    [this, client](asio::error_code ec, std::size_t) {
                        if (!ec) {
                            handleData(client);
                        } else {
                            removeClient(client);
                        }
                    }
                );
            } else {
                // Send failure response
                std::string response = "AUTH_FAILED\n";
                asio::async_write(
                    client->socket,
                    asio::buffer(response),
                    [this, client](asio::error_code, std::size_t) {
                        removeClient(client);
                    }
                );
            }
        }
    );
}

void VpnServer::handleData(std::shared_ptr<ClientConnection> client) {
    auto dataBuffer = std::make_shared<std::array<char, 4096>>();
    
    client->socket.async_read_some(
        asio::buffer(*dataBuffer),
        [this, client, dataBuffer](asio::error_code ec, std::size_t length) {
            if (ec) {
                removeClient(client);
                return;
            }
            
            // Process and route the VPN data here
            // This is where you'd implement the actual VPN logic
            
            // Update stats
            client->bytesTransferred += length;
            
            {
                std::lock_guard<std::mutex> lock(statsMutex_);
                stats_.totalBytesTransferred += length;
            }
            
            // Check bandwidth limit
            uint64_t limit = bandwidthLimitHandler_(client->username, client->isPremium);
            if (client->bytesTransferred > limit) {
                std::cout << "Bandwidth limit reached for " << client->username << std::endl;
                
                // Send bandwidth limit message
                std::string response = "BANDWIDTH_LIMIT_REACHED\n";
                asio::async_write(
                    client->socket,
                    asio::buffer(response),
                    [this, client](asio::error_code, std::size_t) {
                        removeClient(client);
                    }
                );
                return;
            }
            
            // Continue reading data
            handleData(client);
        }
    );
}

void VpnServer::removeClient(std::shared_ptr<ClientConnection> client) {
    if (client->socket.is_open()) {
        asio::error_code ec;
        client->socket.close(ec);
    }
    
    {
        std::lock_guard<std::mutex> lock(clientsMutex_);
        auto it = std::find(clients_.begin(), clients_.end(), client);
        if (it != clients_.end()) {
            clients_.erase(it);
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.activeConnections--;
    }
    
    std::cout << "Client disconnected: " << client->username << std::endl;
}
