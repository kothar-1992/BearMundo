#ifndef BEARMUNDO_CONTAINER_MANAGER_H
#define BEARMUNDO_CONTAINER_MANAGER_H

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
namespace container {

class ContainerManager {
public:
    static ContainerManager& getInstance();
    
    // Core operations
    bool initialize(JNIEnv* env, jobject context);
    void cleanup();
    
    // Container management
    bool createContainer(const std::string& name);
    bool destroyContainer(const std::string& name);
    bool isContainerExists(const std::string& name);
    
    // Container operations
    bool mountContainer(const std::string& name);
    bool unmountContainer(const std::string& name);
    bool isContainerMounted(const std::string& name);
    
    // Container security
    bool protectContainer(const std::string& name);
    bool unprotectContainer(const std::string& name);
    bool isContainerProtected(const std::string& name);
    
    // Container isolation
    bool isolateContainer(const std::string& name);
    bool deisolateContainer(const std::string& name);
    bool isContainerIsolated(const std::string& name);
    
    // Container status
    bool isInitialized() const;
    std::string getLastError() const;
    
private:
    ContainerManager();
    ~ContainerManager();
    
    // Prevent copying
    ContainerManager(const ContainerManager&) = delete;
    ContainerManager& operator=(const ContainerManager&) = delete;
    
    // Internal state
    std::atomic<bool> initialized_{false};
    
    // Threading
    std::mutex mutex_;
    std::condition_variable cv_;
    
    // Error handling
    std::string last_error_;
    void setLastError(const std::string& error);
    
    // Internal utilities
    bool initializeComponents();
    void cleanupComponents();
    
    // Container management methods
    bool createContainerDirectory(const std::string& name);
    bool destroyContainerDirectory(const std::string& name);
    bool isContainerDirectoryExists(const std::string& name);
    
    bool mountContainerDirectory(const std::string& name);
    bool unmountContainerDirectory(const std::string& name);
    bool isContainerDirectoryMounted(const std::string& name);
    
    bool protectContainerDirectory(const std::string& name);
    bool unprotectContainerDirectory(const std::string& name);
    bool isContainerDirectoryProtected(const std::string& name);
    
    bool isolateContainerDirectory(const std::string& name);
    bool deisolateContainerDirectory(const std::string& name);
    bool isContainerDirectoryIsolated(const std::string& name);
    
    // Random number generation
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_int_distribution<int> dis_;
    
    // Configuration
    struct ContainerConfig {
        int max_containers{10};
        int max_container_size{1024 * 1024 * 1024}; // 1GB
        bool enable_logging{true};
        bool enable_encryption{true};
        std::string encryption_key;
    } config_;
    
    // Container tracking
    struct ContainerInfo {
        std::string name;
        bool is_mounted;
        bool is_protected;
        bool is_isolated;
        std::chrono::system_clock::time_point creation_time;
    };
    std::unordered_map<std::string, ContainerInfo> containers_;
};

} // namespace container
} // namespace bearmundo

#endif // BEARMUNDO_CONTAINER_MANAGER_H 