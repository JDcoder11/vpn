#ifndef SUBSCRIPTION_SERVICE_H
#define SUBSCRIPTION_SERVICE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <memory>

// Forward declaration
class AuthService;

/**
 * Subscription management service for VPN users
 */
class SubscriptionService {
public:
    enum class Plan {
        FREE,
        PREMIUM_MONTHLY,
        PREMIUM_YEARLY
    };
    
    struct SubscriptionInfo {
        std::string username;
        Plan plan;
        std::chrono::system_clock::time_point startDate;
        std::chrono::system_clock::time_point endDate;
        bool active;
        std::string stripeSubscriptionId;
    };
    
    // Constructor
    SubscriptionService(std::shared_ptr<AuthService> authService);
    
    // Create a subscription for user
    bool createSubscription(const std::string& username, Plan plan, const std::string& stripeSubscriptionId = "");
    
    // Cancel a subscription
    bool cancelSubscription(const std::string& username);
    
    // Check if user has an active subscription and what type
    bool checkSubscription(const std::string& username, Plan& plan);
    
    // Get subscription details for a user
    bool getSubscriptionDetails(const std::string& username, SubscriptionInfo& info);
    
    // Get all subscriptions
    std::vector<SubscriptionInfo> getAllSubscriptions();
    
    // Check for expired subscriptions and update
    void updateExpiredSubscriptions();

private:
    struct Subscription {
        std::string username;
        Plan plan;
        std::chrono::system_clock::time_point startDate;
        std::chrono::system_clock::time_point endDate;
        bool active;
        std::string stripeSubscriptionId;
    };
    
    std::shared_ptr<AuthService> authService_;
    std::unordered_map<std::string, Subscription> subscriptions_;
    std::mutex subscriptionsMutex_;
    
    // Calculate end date based on plan
    std::chrono::system_clock::time_point calculateEndDate(
        std::chrono::system_clock::time_point startDate, Plan plan);
};

#endif // SUBSCRIPTION_SERVICE_H
