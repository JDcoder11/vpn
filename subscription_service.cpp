#include "subscription_service.h"
#include "auth_service.h"
#include <iostream>

SubscriptionService::SubscriptionService(std::shared_ptr<AuthService> authService)
    : authService_(authService) {
}

bool SubscriptionService::createSubscription(
    const std::string& username, Plan plan, const std::string& stripeSubscriptionId) {
    
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    
    // Update user's premium status in AuthService
    bool isPremium = (plan != Plan::FREE);
    authService_->updatePremiumStatus(username, isPremium);
    
    // Create new subscription
    Subscription subscription;
    subscription.username = username;
    subscription.plan = plan;
    subscription.startDate = std::chrono::system_clock::now();
    subscription.endDate = calculateEndDate(subscription.startDate, plan);
    subscription.active = true;
    subscription.stripeSubscriptionId = stripeSubscriptionId;
    
    // Replace any existing subscription
    subscriptions_[username] = subscription;
    
    std::cout << "Created " 
              << (plan == Plan::FREE ? "free" : 
                  plan == Plan::PREMIUM_MONTHLY ? "monthly premium" : "yearly premium")
              << " subscription for " << username << std::endl;
    
    return true;
}

bool SubscriptionService::cancelSubscription(const std::string& username) {
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    
    auto it = subscriptions_.find(username);
    if (it == subscriptions_.end()) {
        return false;
    }
    
    // Mark subscription as inactive
    it->second.active = false;
    
    // Update user's premium status in AuthService
    authService_->updatePremiumStatus(username, false);
    
    // Create a free plan subscription
    return createSubscription(username, Plan::FREE);
}

bool SubscriptionService::checkSubscription(const std::string& username, Plan& plan) {
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    
    auto it = subscriptions_.find(username);
    if (it == subscriptions_.end() || !it->second.active) {
        return false;
    }
    
    // Check if subscription is expired
    auto now = std::chrono::system_clock::now();
    if (now > it->second.endDate) {
        // If premium subscription expired, downgrade to free
        if (it->second.plan != Plan::FREE) {
            createSubscription(username, Plan::FREE);
        }
        return false;
    }
    
    plan = it->second.plan;
    return true;
}

bool SubscriptionService::getSubscriptionDetails(
    const std::string& username, SubscriptionInfo& info) {
    
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    
    auto it = subscriptions_.find(username);
    if (it == subscriptions_.end()) {
        return false;
    }
    
    info.username = it->second.username;
    info.plan = it->second.plan;
    info.startDate = it->second.startDate;
    info.endDate = it->second.endDate;
    info.active = it->second.active;
    info.stripeSubscriptionId = it->second.stripeSubscriptionId;
    
    return true;
}

std::vector<SubscriptionService::SubscriptionInfo> SubscriptionService::getAllSubscriptions() {
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    
    std::vector<SubscriptionInfo> result;
    for (const auto& pair : subscriptions_) {
        SubscriptionInfo info;
        info.username = pair.second.username;
        info.plan = pair.second.plan;
        info.startDate = pair.second.startDate;
        info.endDate = pair.second.endDate;
        info.active = pair.second.active;
        info.stripeSubscriptionId = pair.second.stripeSubscriptionId;
        
        result.push_back(info);
    }
    
    return result;
}

void SubscriptionService::updateExpiredSubscriptions() {
    std::lock_guard<std::mutex> lock(subscriptionsMutex_);
    
    auto now = std::chrono::system_clock::now();
    for (auto& pair : subscriptions_) {
        if (pair.second.active && now > pair.second.endDate) {
            // If premium subscription expired, downgrade to free
            if (pair.second.plan != Plan::FREE) {
                std::cout << "Premium subscription expired for " << pair.second.username << std::endl;
                pair.second.active = false;
                createSubscription(pair.second.username, Plan::FREE);
            }
        }
    }
}

std::chrono::system_clock::time_point SubscriptionService::calculateEndDate(
    std::chrono::system_clock::time_point startDate, Plan plan) {
    
    switch (plan) {
        case Plan::FREE:
            // Free plan never expires
            return startDate + std::chrono::hours(24 * 365 * 100); // 100 years
            
        case Plan::PREMIUM_MONTHLY:
            // Monthly plan expires after 30 days
            return startDate + std::chrono::hours(24 * 30);
            
        case Plan::PREMIUM_YEARLY:
            // Yearly plan expires after 365 days
            return startDate + std::chrono::hours(24 * 365);
            
        default:
            return startDate;
    }
}
