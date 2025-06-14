#include "ContainerManager.h"
#include <android/log.h>
#include <unistd.h>
#include <sys/stat.h>
#include <chrono>
#include <algorithm>

#define LOG_TAG "BearMundoContainer"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace BearMundo {
namespace Container {

// ========================================
// STATIC MEMBERS
// ========================================

BearMundoContainerManager* BearMundoContainerManager::s_instance = nullptr;
std::mutex BearMundoContainerManager::s_instanceMutex;

// ========================================
// CONTAINER CONFIGURATION
// ========================================

ContainerConfiguration::ContainerConfiguration() 
    : type(ContainerType::STANDARD)
    , securityLevel(SecurityLevel::BASIC)
    , operationMode(OperationMode::NORMAL)
    , enableStealth(false)
    , enableAntiDetection(false)
    , enableMemoryProtection(false) {
}

bool ContainerConfiguration::validate() const {
    // Basic validation
    if (type == ContainerType::STEALTH && !enableStealth) {
        return false;
    }
    
    if (securityLevel == SecurityLevel::MAXIMUM && !enableAntiDetection) {
        return false;
    }
    
    return true;
}

// ========================================
// CONTAINER INSTANCE
// ========================================

ContainerInstance::ContainerInstance(const std::string& id, const ContainerConfiguration& cfg)
    : containerId(id)
    , config(cfg)
    , detectedEnvironment(EnvironmentType::UNKNOWN)
    , isActive(false)
    , securityContext(nullptr) {
    
    auto now = std::chrono::system_clock::now();
    creationTime = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    lastActivity = creationTime;
    
    // Create security context
    securityContext = new RandomizedSecurityContext();
    if (securityContext) {
        securityContext->level = cfg.securityLevel;
        securityContext->mode = cfg.operationMode;
    }
}

ContainerInstance::~ContainerInstance() {
    if (securityContext) {
        delete securityContext;
        securityContext = nullptr;
    }
}

bool ContainerInstance::activate() {
    if (isActive) {
        return true;
    }
    
    if (!config.validate()) {
        LOGE("Container configuration validation failed: %s", containerId.c_str());
        return false;
    }
    
    isActive = true;
    updateActivity();
    
    LOGI("Container activated: %s", containerId.c_str());
    return true;
}

bool ContainerInstance::deactivate() {
    if (!isActive) {
        return true;
    }
    
    isActive = false;
    LOGI("Container deactivated: %s", containerId.c_str());
    return true;
}

bool ContainerInstance::updateActivity() {
    auto now = std::chrono::system_clock::now();
    lastActivity = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return true;
}

bool ContainerInstance::validateSecurity() {
    if (!securityContext) {
        return false;
    }
    
    return securityContext->validateIntegrity();
}

// ========================================
// CONTAINER MANAGER
// ========================================

BearMundoContainerManager::BearMundoContainerManager()
    : m_initialized(false)
    , m_detectedEnvironment(EnvironmentType::UNKNOWN)
    , m_activeContainer(nullptr) {
}

BearMundoContainerManager::~BearMundoContainerManager() {
    std::lock_guard<std::mutex> lock(m_containerMutex);
    m_containers.clear();
    m_activeContainer = nullptr;
}

BearMundoContainerManager* BearMundoContainerManager::getInstance() {
    std::lock_guard<std::mutex> lock(s_instanceMutex);
    if (!s_instance) {
        s_instance = new BearMundoContainerManager();
    }
    return s_instance;
}

bool BearMundoContainerManager::initialize() {
    std::lock_guard<std::mutex> lock(m_containerMutex);
    
    if (m_initialized) {
        return true;
    }
    
    try {
        LOGI("Initializing Bear Mundo Container Manager");
        
        // Detect environment
        m_detectedEnvironment = detectEnvironment();
        LOGI("Detected environment: %d", static_cast<int>(m_detectedEnvironment));
        
        m_initialized = true;
        LOGI("✅ Container Manager initialized successfully");
        
        return true;
        
    } catch (const std::exception& e) {
        LOGE("Exception during container manager initialization: %s", e.what());
        return false;
    }
}

bool BearMundoContainerManager::isManagerInitialized() const {
    return m_initialized;
}

EnvironmentType BearMundoContainerManager::detectEnvironment() {
    // Check for root access
    if (access("/system/bin/su", F_OK) == 0 || access("/system/xbin/su", F_OK) == 0) {
        return EnvironmentType::ROOT;
    }
    
    // Check for emulator characteristics
    if (access("/system/bin/qemu-props", F_OK) == 0) {
        return EnvironmentType::EMULATOR;
    }
    
    return EnvironmentType::NON_ROOT;
}

bool BearMundoContainerManager::isRootEnvironment() const {
    return m_detectedEnvironment == EnvironmentType::ROOT;
}

bool BearMundoContainerManager::isEmulatorEnvironment() const {
    return m_detectedEnvironment == EnvironmentType::EMULATOR;
}

EnvironmentType BearMundoContainerManager::getDetectedEnvironment() const {
    return m_detectedEnvironment;
}

std::string BearMundoContainerManager::generateContainerId() {
    const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result = "container_";
    
    static std::random_device rd;
    static std::mt19937 gen(rd());
    
    for (int i = 0; i < 16; ++i) {
        result += chars[gen() % (sizeof(chars) - 1)];
    }
    
    return result;
}

std::string BearMundoContainerManager::createContainer(const ContainerConfiguration& config) {
    std::lock_guard<std::mutex> lock(m_containerMutex);
    
    if (!m_initialized) {
        LOGE("Container manager not initialized");
        return "";
    }
    
    if (!config.validate()) {
        LOGE("Invalid container configuration");
        return "";
    }
    
    std::string containerId = generateContainerId();
    auto container = std::make_unique<ContainerInstance>(containerId, config);
    container->detectedEnvironment = m_detectedEnvironment;
    
    m_containers[containerId] = std::move(container);
    
    LOGI("Container created: %s", containerId.c_str());
    return containerId;
}

bool BearMundoContainerManager::activateContainer(const std::string& containerId) {
    std::lock_guard<std::mutex> lock(m_containerMutex);
    
    auto it = m_containers.find(containerId);
    if (it == m_containers.end()) {
        LOGE("Container not found: %s", containerId.c_str());
        return false;
    }
    
    // Deactivate current active container
    if (m_activeContainer) {
        m_activeContainer->deactivate();
    }
    
    // Activate new container
    if (it->second->activate()) {
        m_activeContainer = it->second.get();
        return true;
    }
    
    return false;
}

bool BearMundoContainerManager::deactivateContainer(const std::string& containerId) {
    std::lock_guard<std::mutex> lock(m_containerMutex);
    
    auto it = m_containers.find(containerId);
    if (it == m_containers.end()) {
        return false;
    }
    
    bool result = it->second->deactivate();
    
    if (m_activeContainer == it->second.get()) {
        m_activeContainer = nullptr;
    }
    
    return result;
}

ContainerInstance* BearMundoContainerManager::getActiveContainer() {
    std::lock_guard<std::mutex> lock(m_containerMutex);
    return m_activeContainer;
}

ContainerInstance* BearMundoContainerManager::getContainer(const std::string& containerId) {
    std::lock_guard<std::mutex> lock(m_containerMutex);
    
    auto it = m_containers.find(containerId);
    if (it != m_containers.end()) {
        return it->second.get();
    }
    
    return nullptr;
}

size_t BearMundoContainerManager::getContainerCount() const {
    std::lock_guard<std::mutex> lock(m_containerMutex);
    return m_containers.size();
}

// ========================================
// CONTAINER FACTORY FUNCTIONS
// ========================================

ContainerConfiguration createStandardConfiguration() {
    ContainerConfiguration config;
    config.type = ContainerType::STANDARD;
    config.securityLevel = SecurityLevel::BASIC;
    config.operationMode = OperationMode::NORMAL;
    config.enableStealth = false;
    config.enableAntiDetection = false;
    config.enableMemoryProtection = true;
    return config;
}

ContainerConfiguration createRootConfiguration() {
    ContainerConfiguration config;
    config.type = ContainerType::PRIVILEGED;
    config.securityLevel = SecurityLevel::ENHANCED;
    config.operationMode = OperationMode::NORMAL;
    config.enableStealth = false;
    config.enableAntiDetection = true;
    config.enableMemoryProtection = true;
    return config;
}

ContainerConfiguration createNonRootConfiguration() {
    ContainerConfiguration config;
    config.type = ContainerType::STANDARD;
    config.securityLevel = SecurityLevel::BASIC;
    config.operationMode = OperationMode::NORMAL;
    config.enableStealth = false;
    config.enableAntiDetection = false;
    config.enableMemoryProtection = true;
    return config;
}

ContainerConfiguration createStealthConfiguration() {
    ContainerConfiguration config;
    config.type = ContainerType::STEALTH;
    config.securityLevel = SecurityLevel::MAXIMUM;
    config.operationMode = OperationMode::STEALTH;
    config.enableStealth = true;
    config.enableAntiDetection = true;
    config.enableMemoryProtection = true;
    return config;
}

ContainerConfiguration createDecoyConfiguration() {
    ContainerConfiguration config;
    config.type = ContainerType::DECOY;
    config.securityLevel = SecurityLevel::ENHANCED;
    config.operationMode = OperationMode::DECOY;
    config.enableStealth = false;
    config.enableAntiDetection = true;
    config.enableMemoryProtection = false;
    return config;
}

bool validateContainerConfig(const ContainerConfiguration& config) {
    return config.validate();
}

ContainerConfiguration getRecommendedConfiguration(EnvironmentType env) {
    switch (env) {
        case EnvironmentType::ROOT:
            return createRootConfiguration();
        case EnvironmentType::EMULATOR:
            return createStealthConfiguration();
        case EnvironmentType::NON_ROOT:
        default:
            return createNonRootConfiguration();
    }
}

bool isConfigurationCompatible(const ContainerConfiguration& config, EnvironmentType env) {
    if (config.type == ContainerType::PRIVILEGED && env != EnvironmentType::ROOT) {
        return false;
    }
    return true;
}

std::string generateSecureContainerId() {
    BearMundoContainerManager* manager = BearMundoContainerManager::getInstance();
    if (manager) {
        return manager->generateContainerId();
    }
    return "container_default";
}

} // namespace Container
} // namespace BearMundo
