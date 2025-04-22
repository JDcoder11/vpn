#ifndef AUTH_SERVICE_H
#define AUTH_SERVICE_H

#include <string>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <vector>

/**
 * JWT Authentication service for VPN users
 */
class AuthService {
public:
    // Constructor - takes the JWT secret key
    AuthService(const std::string& secretKey);
    
    // Register a new user
    bool registerUser(const std::string& username, const std::string& password, const std::string& email);
    
    // Login a user and generate a JWT token
    std::string loginUser(const std::string& username, const std::string& password);
    
    // Verify a JWT token and extract user information
    bool verifyToken(const std::string& token, std::string& username, bool& isPremium);
    
    // Update user's premium status
    bool updatePremiumStatus(const std::string& username, bool isPremium);
    
    // Get all users
    struct UserInfo {
        std::string username;
        std::string email;
        bool isPremium;
    };
    
    std::vector<UserInfo> getAllUsers();

private:
    struct User {
        std::string username;
        std::string passwordHash;
        std::string email;
        bool isPremium;
    };
    
    // Generate a JWT token for a user
    std::string generateToken(const std::string& username, bool isPremium);
    
    // Hash a password
    std::string hashPassword(const std::string& password);
    
    // Verify a password against its hash
    bool verifyPassword(const std::string& password, const std::string& hash);
    
    std::string secretKey_;
    std::unordered_map<std::string, User> users_;
    std::mutex usersMutex_;
};

#endif // AUTH_SERVICE_H