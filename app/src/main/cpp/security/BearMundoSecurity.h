#ifndef BEARMUNDO_SECURITY_H
#define BEARMUNDO_SECURITY_H

#include <jni.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <random>
#include <functional>
#include <unordered_map>
#include <thread>
#include <condition_variable>

namespace bearmundo {
namespace security {

// Forward declarations
class StealthOperations;
class AntiDetection;
class ContainerManager;
class MemoryProtection;

class BearMundoSecurity {
public:
    static BearMundoSecurity& getInstance();
    
    // Core initialization
    bool initialize(JNIEnv* env, jobject context);
    void cleanup();
    
    // Security operations
    bool validateEnvironment();
    bool checkIntegrity();
    bool verifyAuthentication();
    bool protectMemory();
    
    // Container management
    bool createSecureContainer();
    bool destroySecureContainer();
    bool isContainerSecure();
    
    // Stealth operations
    bool enableStealthMode();
    bool disableStealthMode();
    bool isStealthActive();
    
    // Anti-detection
    bool checkForDebugger();
    bool checkForEmulator();
    bool checkForRoot();
    bool checkForTampering();
    
    // Memory protection
    bool protectMemoryRegion(void* address, size_t size);
    bool unprotectMemoryRegion(void* address);
    bool isMemoryProtected(void* address);
    
    // Thread management
    bool createSecureThread(std::function<void()> task);
    bool destroySecureThread();
    bool isThreadSecure();
    
    // Configuration
    void setSecurityLevel(int level);
    void setStealthLevel(int level);
    void setContainerMode(int mode);
    
    // Status
    bool isInitialized() const;
    bool isSecure() const;
    std::string getLastError() const;
    
private:
    BearMundoSecurity();
    ~BearMundoSecurity();
    
    // Prevent copying
    BearMundoSecurity(const BearMundoSecurity&) = delete;
    BearMundoSecurity& operator=(const BearMundoSecurity&) = delete;
    
    // Internal state
    std::atomic<bool> initialized_{false};
    std::atomic<bool> secure_{false};
    std::atomic<bool> stealth_active_{false};
    std::atomic<int> security_level_{0};
    std::atomic<int> stealth_level_{0};
    std::atomic<int> container_mode_{0};
    
    // Components
    std::unique_ptr<StealthOperations> stealth_ops_;
    std::unique_ptr<AntiDetection> anti_detection_;
    std::unique_ptr<ContainerManager> container_manager_;
    std::unique_ptr<MemoryProtection> memory_protection_;
    
    // Threading
    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread secure_thread_;
    std::atomic<bool> thread_running_{false};
    
    // Error handling
    std::string last_error_;
    void setLastError(const std::string& error);
    
    // Internal utilities
    bool initializeComponents();
    bool validateComponents();
    void cleanupComponents();
    
    // Security checks
    bool performSecurityChecks();
    bool validateMemoryProtection();
    bool validateContainerSecurity();
    bool validateStealthOperations();
    
    // Random number generation
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<int> dis_;
    
    // Configuration
    struct SecurityConfig {
        int max_retries{3};
        int timeout_ms{5000};
        bool enable_logging{true};
        bool enable_encryption{true};
        std::string encryption_key;
    } config_;
    
    // Memory tracking
    struct MemoryRegion {
        void* address;
        size_t size;
        bool is_protected;
        std::chrono::system_clock::time_point protection_time;
    };
    std::vector<MemoryRegion> protected_regions_;
    
    // Thread management
    struct ThreadInfo {
        std::thread::id id;
        bool is_protected;
        std::chrono::system_clock::time_point start_time;
    };
    std::unordered_map<std::thread::id, ThreadInfo> thread_info_;
};

} // namespace security
} // namespace bearmundo

#endif // BEARMUNDO_SECURITY_H 