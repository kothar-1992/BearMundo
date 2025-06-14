#ifndef BEAR_MUNDO_CONTAINER_MANAGER_H
#define BEAR_MUNDO_CONTAINER_MANAGER_H

#include "BearMundoSecurity.h"
#include <memory>
#include <vector>
#include <unordered_map>

namespace BearMundo {
namespace Container {

// ========================================
// CONTAINER TYPE DEFINITIONS
// ========================================

enum class ContainerType {
    STANDARD = 0,
    PRIVILEGED = 1,
    STEALTH = 2,
    DECOY = 3
};

enum class EnvironmentType {
    UNKNOWN = 0,
    ROOT = 1,
    NON_ROOT = 2,
    EMULATOR = 3,
    VIRTUAL = 4
};

// ========================================
// CONTAINER CONFIGURATION
// ========================================

struct ContainerConfiguration {
    ContainerType type;
    SecurityLevel securityLevel;
    OperationMode operationMode;
    bool enableStealth;
    bool enableAntiDetection;
    bool enableMemoryProtection;
    std::string customIdentifier;
    
    ContainerConfiguration();
    bool validate() const;
};

// ========================================
// CONTAINER INSTANCE
// ========================================

struct ContainerInstance {
    std::string containerId;
    ContainerConfiguration config;
    EnvironmentType detectedEnvironment;
    uint64_t creationTime;
    uint64_t lastActivity;
    bool isActive;
    RandomizedSecurityContext* securityContext;
    
    ContainerInstance(const std::string& id, const ContainerConfiguration& cfg);
    ~ContainerInstance();
    
    bool activate();
    bool deactivate();
    bool updateActivity();
    bool validateSecurity();
};

// ========================================
// CONTAINER MANAGER
// ========================================

class BearMundoContainerManager {
private:
    static BearMundoContainerManager* s_instance;
    static std::mutex s_instanceMutex;
    
    bool m_initialized;
    EnvironmentType m_detectedEnvironment;
    std::unordered_map<std::string, std::unique_ptr<ContainerInstance>> m_containers;
    ContainerInstance* m_activeContainer;
    std::mutex m_containerMutex;
    
    // Private constructor for singleton
    BearMundoContainerManager();
    
    // Detect runtime environment
    EnvironmentType detectEnvironment();
    
    // Generate unique container ID
    std::string generateContainerId();

public:
    // Singleton access
    static BearMundoContainerManager* getInstance();
    
    // Destructor
    ~BearMundoContainerManager();
    
    // Initialize the container manager
    bool initialize();
    
    // Check if manager is initialized
    bool isManagerInitialized() const;
    
    // Environment detection
    bool isRootEnvironment() const;
    bool isEmulatorEnvironment() const;
    EnvironmentType getDetectedEnvironment() const;
    
    // Container management
    std::string createContainer(const ContainerConfiguration& config);
    bool activateContainer(const std::string& containerId);
    bool deactivateContainer(const std::string& containerId);
    bool destroyContainer(const std::string& containerId);
    
    // Container access
    ContainerInstance* getActiveContainer();
    ContainerInstance* getContainer(const std::string& containerId);
    std::vector<std::string> listContainers() const;
    
    // Security operations
    bool validateAllContainers();
    bool performSecurityScan();
    void cleanupInactiveContainers();
    
    // Statistics
    size_t getContainerCount() const;
    uint64_t getTotalUptime() const;
};

// ========================================
// CONTAINER FACTORY FUNCTIONS
// ========================================

/**
 * Create standard container configuration
 */
ContainerConfiguration createStandardConfiguration();

/**
 * Create root-privileged container configuration
 */
ContainerConfiguration createRootConfiguration();

/**
 * Create non-root container configuration
 */
ContainerConfiguration createNonRootConfiguration();

/**
 * Create stealth container configuration
 */
ContainerConfiguration createStealthConfiguration();

/**
 * Create decoy container configuration
 */
ContainerConfiguration createDecoyConfiguration();

// ========================================
// CONTAINER UTILITIES
// ========================================

/**
 * Validate container configuration
 */
bool validateContainerConfig(const ContainerConfiguration& config);

/**
 * Get recommended configuration for environment
 */
ContainerConfiguration getRecommendedConfiguration(EnvironmentType env);

/**
 * Check container compatibility
 */
bool isConfigurationCompatible(const ContainerConfiguration& config, EnvironmentType env);

/**
 * Generate secure container identifier
 */
std::string generateSecureContainerId();

/**
 * Encrypt container data
 */
std::vector<uint8_t> encryptContainerData(const std::vector<uint8_t>& data, const std::string& key);

/**
 * Decrypt container data
 */
std::vector<uint8_t> decryptContainerData(const std::vector<uint8_t>& encryptedData, const std::string& key);

} // namespace Container
} // namespace BearMundo

#endif // BEAR_MUNDO_CONTAINER_MANAGER_H
