#ifndef BEARMUNDO_STEALTH_OPERATIONS_H
#define BEARMUNDO_STEALTH_OPERATIONS_H

#include <android/log.h>
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

#ifdef __cplusplus
extern "C" {
#endif

#include <jni.h>

#ifdef __cplusplus
}
#endif

namespace bearmundo {
namespace stealth {

class StealthOperations {
public:
    static StealthOperations& getInstance();
    
    // Core operations
    bool initialize(JNIEnv* env, jobject context);
    void cleanup();
    
    // Hook detection
    bool checkForHooks();
    bool checkForDebugger();
    bool checkForEmulator();
    bool checkForRoot();
    
    // Memory protection
    bool protectMemoryRegion(void* address, size_t size);
    bool unprotectMemoryRegion(void* address);
    bool isMemoryProtected(void* address);
    
    // Thread protection
    bool protectThread(std::thread::id thread_id);
    bool unprotectThread(std::thread::id thread_id);
    bool isThreadProtected(std::thread::id thread_id);
    
    // Anti-analysis
    bool enableAntiAnalysis();
    bool disableAntiAnalysis();
    bool isAntiAnalysisEnabled();
    
    // Stealth mode
    bool enableStealthMode();
    bool disableStealthMode();
    bool isStealthModeEnabled();
    
    // Status
    bool isInitialized() const;
    std::string getLastError() const;
    
private:
    StealthOperations();
    ~StealthOperations();
    
    // Prevent copying
    StealthOperations(const StealthOperations&) = delete;
    StealthOperations& operator=(const StealthOperations&) = delete;
    
    // Internal state
    std::atomic<bool> initialized_{false};
    std::atomic<bool> anti_analysis_enabled_{false};
    std::atomic<bool> stealth_mode_enabled_{false};
    
    // Threading
    std::mutex mutex_;
    std::condition_variable cv_;
    std::unordered_map<std::thread::id, bool> protected_threads_;
    
    // Error handling
    std::string last_error_;
    void setLastError(const std::string& error);
    
    // Internal utilities
    bool initializeComponents();
    void cleanupComponents();
    
    // Hook detection methods
    bool checkForXposed();
    bool checkForFrida();
    bool checkForSubstrate();
    bool checkForMagisk();
    
    // Memory protection methods
    bool protectMemoryPage(void* address);
    bool unprotectMemoryPage(void* address);
    bool isMemoryPageProtected(void* address);
    
    // Thread protection methods
    bool protectThreadStack(std::thread::id thread_id);
    bool unprotectThreadStack(std::thread::id thread_id);
    bool isThreadStackProtected(std::thread::id thread_id);
    
    // Anti-analysis methods
    bool enableMemoryProtection();
    bool enableThreadProtection();
    bool enableHookDetection();
    
    // Stealth mode methods
    bool enableProcessHiding();
    bool enableLibraryHiding();
    bool enableSymbolHiding();
    
    // Random number generation
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<int> dis_;
    
    // Configuration
    struct StealthConfig {
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
    
    // Thread tracking
    struct ThreadInfo {
        std::thread::id id;
        bool is_protected;
        std::chrono::system_clock::time_point protection_time;
    };
    std::unordered_map<std::thread::id, ThreadInfo> thread_info_;
};

} // namespace stealth
} // namespace bearmundo

#endif // BEARMUNDO_STEALTH_OPERATIONS_H 