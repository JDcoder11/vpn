#define ASIO_STANDALONE
#include <asio.hpp>
#include <asio\any_completion_executor.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include <cstdlib>

#include "vpn_server.h"
#include "auth_service.h"
#include "subscription_service.h"
#include "wireguard_manager.h"

using json = nlohmann::json;
using asio::ip::tcp;

// Structure to hold the application configuration
struct AppConfig {
    std::string jwt_secret;
    unsigned short api_port;
    unsigned short vpn_port;
};

// Read environment variables or use defaults
AppConfig getConfig() {
    AppConfig config;
    
    // Get JWT secret from environment variable or use default
    const char* jwt_secret = std::getenv("JWT_SECRET");
    config.jwt_secret = jwt_secret ? jwt_secret : "secure_vpn_secret_key";
    
    // Get API port from environment variable or use default
    const char* api_port_str = std::getenv("API_PORT");
    config.api_port = api_port_str ? std::stoi(api_port_str) : 8000;
    
    // Get VPN port from environment variable or use default
    const char* vpn_port_str = std::getenv("VPN_PORT");
    config.vpn_port = vpn_port_str ? std::stoi(vpn_port_str) : 51820;
    
    return config;
}

// API request handler
class APIRequestHandler : public std::enable_shared_from_this<APIRequestHandler> {
public:
    APIRequestHandler(
        std::shared_ptr<asio::io_context> io_context,
        std::shared_ptr<AuthService> auth_service,
        std::shared_ptr<SubscriptionService> subscription_service,
        std::shared_ptr<WireGuardManager> wireguard_manager
    ) : 
        io_context_(io_context),
        auth_service_(auth_service),
        subscription_service_(subscription_service),
        wireguard_manager_(wireguard_manager) {}
    
    void handleRequest(tcp::socket socket) {
        auto self = shared_from_this();
        
        std::make_shared<Session>(std::move(socket), auth_service_, subscription_service_, wireguard_manager_)->start();
    }

private:
    // Session to handle a single client connection
    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(
            tcp::socket socket,
            std::shared_ptr<AuthService> auth_service,
            std::shared_ptr<SubscriptionService> subscription_service,
            std::shared_ptr<WireGuardManager> wireguard_manager
        ) : 
            socket_(std::move(socket)),
            auth_service_(auth_service),
            subscription_service_(subscription_service),
            wireguard_manager_(wireguard_manager) {}
        
        void start() {
            readRequest();
        }
        
    private:
        void readRequest() {
            auto self = shared_from_this();
            
            asio::async_read_until(
                socket_,
                buffer_,
                "\r\n\r\n",
                [this, self](std::error_code ec, std::size_t length) {
                    if (!ec) {
                        // Convert buffer to string
                        std::string request_str(
                            asio::buffers_begin(buffer_.data()),
                            asio::buffers_begin(buffer_.data()) + length
                        );
                        
                        // Parse request and process
                        processRequest(request_str);
                    }
                }
            );
        }
        
        void processRequest(const std::string& request) {
            // Parse HTTP request (simplified for example)
            std::string method, path;
            std::istringstream req_stream(request);
            req_stream >> method >> path;
            
            // Response content
            std::string response_body;
            std::string content_type = "application/json";
            int status_code = 200;
            
            try {
                // Route API requests based on path and method
                if (path == "/api/auth/register" && method == "POST") {
                    // Registration endpoint
                    json request_body = getRequestBody(request);
                    response_body = handleRegistration(request_body);
                }
                else if (path == "/api/auth/login" && method == "POST") {
                    // Login endpoint
                    json request_body = getRequestBody(request);
                    response_body = handleLogin(request_body);
                }
                else if (path == "/api/servers" && method == "GET") {
                    // Get available servers
                    response_body = handleGetServers(request);
                }
                else if (path == "/api/subscriptions" && method == "POST") {
                    // Create subscription
                    json request_body = getRequestBody(request);
                    response_body = handleCreateSubscription(request, request_body);
                }
                else if (path == "/api/connections" && method == "POST") {
                    // Create VPN connection
                    json request_body = getRequestBody(request);
                    response_body = handleCreateConnection(request, request_body);
                }
                else if (path.find("/api/connections/") == 0 && path.find("/close") != std::string::npos && method == "POST") {
                    // Close VPN connection
                    response_body = handleCloseConnection(request, path);
                }
                else if (path == "/api/wireguard/config" && method == "GET") {
                    // Get WireGuard config
                    response_body = handleGetWireGuardConfig(request);
                    content_type = "text/plain";
                }
                else {
                    // Endpoint not found
                    status_code = 404;
                    response_body = "{\"error\": \"Endpoint not found\"}";
                }
            }
            catch (const std::exception& e) {
                // Handle any exceptions
                status_code = 500;
                response_body = "{\"error\": \"Internal server error: " + std::string(e.what()) + "\"}";
            }
            
            // Send response
            sendResponse(status_code, content_type, response_body);
        }
        
        json getRequestBody(const std::string& request) {
            // Find the start of JSON body after headers
            size_t body_pos = request.find("\r\n\r\n");
            if (body_pos == std::string::npos) {
                return json::object();
            }
            
            std::string body = request.substr(body_pos + 4);
            return json::parse(body);
        }
        
        std::string getAuthToken(const std::string& request) {
            // Extract Authorization header
            std::istringstream req_stream(request);
            std::string line;
            
            while (std::getline(req_stream, line) && line != "\r") {
                if (line.find("Authorization: Bearer ") == 0) {
                    return line.substr(22); // Skip "Authorization: Bearer "
                }
            }
            
            return "";
        }
        
        std::string handleRegistration(const json& request_body) {
            // Extract user details
            std::string username = request_body["username"];
            std::string password = request_body["password"];
            std::string email = request_body["email"];
            
            // Register user
            bool success = auth_service_->registerUser(username, password, email);
            
            if (success) {
                // Create free subscription
                subscription_service_->createSubscription(username, SubscriptionService::Plan::FREE);
                
                return "{\"status\": \"success\", \"message\": \"User registered successfully\"}";
            } else {
                return "{\"status\": \"error\", \"message\": \"Username already exists\"}";
            }
        }
        
        std::string handleLogin(const json& request_body) {
            // Extract login details
            std::string username = request_body["username"];
            std::string password = request_body["password"];
            
            // Attempt login
            std::string token = auth_service_->loginUser(username, password);
            
            if (!token.empty()) {
                json response;
                response["status"] = "success";
                response["token"] = token;
                
                // Get user's subscription status
                SubscriptionService::Plan plan;
                bool has_subscription = subscription_service_->checkSubscription(username, plan);
                bool is_premium = has_subscription && plan != SubscriptionService::Plan::FREE;
                
                response["user"] = {
                    {"username", username},
                    {"isPremium", is_premium}
                };
                
                return response.dump();
            } else {
                return "{\"status\": \"error\", \"message\": \"Invalid username or password\"}";
            }
        }
        
        std::string handleGetServers(const std::string& request) {
            std::string token = getAuthToken(request);
            
            // Verify token
            std::string username;
            bool is_premium;
            if (!auth_service_->verifyToken(token, username, is_premium)) {
                return "{\"status\": \"error\", \"message\": \"Unauthorized\"}";
            }
            
            // Get servers based on premium status
            std::vector<WireGuardManager::ServerInfo> servers;
            if (is_premium) {
                servers = wireguard_manager_->getAllServers();
            } else {
                servers = wireguard_manager_->getFreeServers();
            }
            
            // Convert to JSON
            json response;
            response["status"] = "success";
            response["servers"] = json::array();
            
            for (const auto& server : servers) {
                response["servers"].push_back({
                    {"name", server.name},
                    {"location", server.location},
                    {"status", server.status},
                    {"premiumOnly", server.premiumOnly},
                    {"bandwidth", server.bandwidth},
                    {"usedBandwidth", server.usedBandwidth}
                });
            }
            
            return response.dump();
        }
        
        std::string handleCreateSubscription(const std::string& request, const json& request_body) {
            std::string token = getAuthToken(request);
            
            // Verify token
            std::string username;
            bool is_premium;
            if (!auth_service_->verifyToken(token, username, is_premium)) {
                return "{\"status\": \"error\", \"message\": \"Unauthorized\"}";
            }
            
            // Extract plan
            std::string plan_str = request_body["plan"];
            SubscriptionService::Plan plan;
            
            if (plan_str == "premium_monthly") {
                plan = SubscriptionService::Plan::PREMIUM_MONTHLY;
            } else if (plan_str == "premium_yearly") {
                plan = SubscriptionService::Plan::PREMIUM_YEARLY;
            } else {
                return "{\"status\": \"error\", \"message\": \"Invalid plan\"}";
            }
            
            // Create subscription
            bool success = subscription_service_->createSubscription(
                username, plan, request_body.value("stripeSubscriptionId", "")
            );
            
            // Update user's premium status
            auth_service_->updatePremiumStatus(username, true);
            
            if (success) {
                return "{\"status\": \"success\", \"message\": \"Subscription created\"}";
            } else {
                return "{\"status\": \"error\", \"message\": \"Failed to create subscription\"}";
            }
        }
        
        std::string handleCreateConnection(const std::string& request, const json& request_body) {
            std::string token = getAuthToken(request);
            
            // Verify token
            std::string username;
            bool is_premium;
            if (!auth_service_->verifyToken(token, username, is_premium)) {
                return "{\"status\": \"error\", \"message\": \"Unauthorized\"}";
            }
            
            // Extract server name
            std::string server_name = request_body["serverName"];
            
            // Get server info
            WireGuardManager::ServerInfo server_info;
            if (!wireguard_manager_->getServerInfo(server_name, server_info)) {
                return "{\"status\": \"error\", \"message\": \"Server not found\"}";
            }
            
            // Check if premium-only server and user is not premium
            if (server_info.premiumOnly && !is_premium) {
                return "{\"status\": \"error\", \"message\": \"Premium subscription required\"}";
            }
            
            // Generate client config
            WireGuardManager::ClientConfig client_config;
            if (!wireguard_manager_->generateClientConfig(server_name, username, is_premium, client_config)) {
                return "{\"status\": \"error\", \"message\": \"Failed to generate client configuration\"}";
            }
            
            // Return connection details
            json response;
            response["status"] = "success";
            response["connection"] = {
                {"serverName", server_name},
                {"serverLocation", server_info.location},
                {"config", {
                    {"interface", client_config.interface},
                    {"privateKey", client_config.privateKey},
                    {"address", client_config.address},
                    {"dns", client_config.dns},
                    {"publicKey", client_config.publicKey},
                    {"endpoint", client_config.endpoint},
                    {"allowedIPs", client_config.allowedIPs},
                    {"keepalive", client_config.keepalive}
                }}
            };
            
            return response.dump();
        }
        
        std::string handleCloseConnection(const std::string& request, const std::string& path) {
            std::string token = getAuthToken(request);
            
            // Verify token
            std::string username;
            bool is_premium;
            if (!auth_service_->verifyToken(token, username, is_premium)) {
                return "{\"status\": \"error\", \"message\": \"Unauthorized\"}";
            }
            
            // In a real implementation, this would track and close an active connection
            // For demo purposes, we'll just return success
            
            return "{\"status\": \"success\", \"message\": \"Connection closed\"}";
        }
        
        std::string handleGetWireGuardConfig(const std::string& request) {
            std::string token = getAuthToken(request);
            
            // Verify token
            std::string username;
            bool is_premium;
            if (!auth_service_->verifyToken(token, username, is_premium)) {
                return "{\"status\": \"error\", \"message\": \"Unauthorized\"}";
            }
            
            // Extract query parameters for server name
            // In a real implementation, parse query string
            std::string server_name = "US-Free"; // Default server
            
            // Generate client config
            WireGuardManager::ClientConfig client_config;
            if (!wireguard_manager_->generateClientConfig(server_name, username, is_premium, client_config)) {
                return "{\"status\": \"error\", \"message\": \"Failed to generate client configuration\"}";
            }
            
            // Format as WireGuard config file
            std::string config = 
                client_config.interface + "\n" +
                client_config.privateKey + "\n" +
                client_config.address + "\n" +
                client_config.dns + "\n\n" +
                "[Peer]\n" +
                client_config.publicKey + "\n" +
                client_config.endpoint + "\n" +
                client_config.allowedIPs + "\n" +
                "PersistentKeepalive = " + std::to_string(client_config.keepalive);
            
            return config;
        }
        
        void sendResponse(int status_code, const std::string& content_type, const std::string& body) {
            std::string status_text;
            switch (status_code) {
                case 200: status_text = "OK"; break;
                case 201: status_text = "Created"; break;
                case 400: status_text = "Bad Request"; break;
                case 401: status_text = "Unauthorized"; break;
                case 403: status_text = "Forbidden"; break;
                case 404: status_text = "Not Found"; break;
                case 500: status_text = "Internal Server Error"; break;
                default: status_text = "Unknown"; break;
            }
            
            std::string response = 
                "HTTP/1.1 " + std::to_string(status_code) + " " + status_text + "\r\n" +
                "Content-Type: " + content_type + "\r\n" +
                "Content-Length: " + std::to_string(body.length()) + "\r\n" +
                "Connection: close\r\n" +
                "\r\n" +
                body;
            
            asio::async_write(
                socket_,
                asio::buffer(response),
                [this](std::error_code ec, std::size_t) {
                    // Close the socket when done sending
                    if (!ec) {
                        socket_.close();
                    }
                }
            );
        }
        
        tcp::socket socket_;
        asio::streambuf buffer_;
        std::shared_ptr<AuthService> auth_service_;
        std::shared_ptr<SubscriptionService> subscription_service_;
        std::shared_ptr<WireGuardManager> wireguard_manager_;
    };
    
    std::shared_ptr<asio::io_context> io_context_;
    std::shared_ptr<AuthService> auth_service_;
    std::shared_ptr<SubscriptionService> subscription_service_;
    std::shared_ptr<WireGuardManager> wireguard_manager_;
};

int main() {
    try {
        // Get configuration
        AppConfig config = getConfig();
        
        std::cout << "Starting SecureVPN server..." << std::endl;
        std::cout << "API Port: " << config.api_port << std::endl;
        std::cout << "VPN Port: " << config.vpn_port << std::endl;
        
        // Create IO context
        auto io_context = std::make_shared<asio::io_context>();
        
        // Create services
        auto auth_service = std::make_shared<AuthService>(config.jwt_secret);
        auto subscription_service = std::make_shared<SubscriptionService>(auth_service);
        auto wireguard_manager = std::make_shared<WireGuardManager>();
        
        // Create VPN server
        VpnServer vpn_server(config.vpn_port);
        
        // Set up authentication handler for VPN server
        vpn_server.setAuthHandler(
            [auth_service](const std::string& token, std::string& username, bool& isPremium) {
                return auth_service->verifyToken(token, username, isPremium);
            }
        );
        
        // Set up bandwidth handler for VPN server
        vpn_server.setBandwidthLimitHandler(
            [subscription_service](const std::string& username, bool isPremium) {
                SubscriptionService::Plan plan;
                bool has_subscription = subscription_service->checkSubscription(username, plan);
                
                // Return bandwidth limit in bytes
                if (has_subscription) {
                    switch (plan) {
                        case SubscriptionService::Plan::FREE:
                            return 2ULL * 1024 * 1024 * 1024; // 2GB
                        case SubscriptionService::Plan::PREMIUM_MONTHLY:
                        case SubscriptionService::Plan::PREMIUM_YEARLY:
                            return 100ULL * 1024 * 1024 * 1024; // 100GB
                        default:
                            return 1ULL * 1024 * 1024 * 1024; // 1GB default
                    }
                } else {
                    return 1ULL * 1024 * 1024 * 1024; // 1GB default
                }
            }
        );
        
        // Start VPN server
        vpn_server.start();
        
        // Setup API server
        tcp::acceptor acceptor(*io_context, tcp::endpoint(tcp::v4(), config.api_port));
        
        // Create API request handler
        auto request_handler = std::make_shared<APIRequestHandler>(
            io_context, auth_service, subscription_service, wireguard_manager
        );
        
        // Accept API connections
        std::function<void()> doAccept;
        doAccept = [&acceptor, request_handler, &doAccept]() {
            acceptor.async_accept(
                [request_handler, &acceptor, &doAccept](std::error_code ec, tcp::socket socket) {
                    if (!ec) {
                        request_handler->handleRequest(std::move(socket));
                    }
                    
                    // Accept next connection
                    doAccept();
                }
            );
        };
        
        doAccept();
        
        // Run IO context
        std::cout << "Server started, waiting for connections..." << std::endl;
        io_context->run();
        
    } catch (std::exception& e) {
        std::cerr << "Exception in main: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}