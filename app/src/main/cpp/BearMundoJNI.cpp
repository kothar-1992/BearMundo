#include <jni.h>
#include "BearMundoSecurity.h"
#include "ContainerManager.h"
#include <android/log.h>

#define LOG_TAG "BearMundoJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

// ========================================
// BEAR MUNDO CORE FUNCTIONS
// ========================================

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_initializeBearMundoSecurity(JNIEnv *env, jclass clazz) {
    return BearMundo::initializeBearMundoSecurity(env);
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_isBearMundoActive(JNIEnv *env, jclass clazz) {
    return BearMundo::isBearMundoSecurityActive();
}

JNIEXPORT jint JNICALL
Java_com_bearmod_security_BearMundoSecurity_getSecurityLevel(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(BearMundo::getCurrentSecurityLevel());
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_enableStealthMode(JNIEnv *env, jclass clazz) {
    return BearMundo::enableStealthMode();
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_disableStealthMode(JNIEnv *env, jclass clazz) {
    return BearMundo::disableStealthMode();
}

JNIEXPORT jint JNICALL
Java_com_bearmod_security_BearMundoSecurity_performThreatAssessment(JNIEnv *env, jclass clazz) {
    BearMundo::DetectionThreat threat = BearMundo::validateSecurityEnvironment();
    return static_cast<jint>(threat);
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_validateKeyAuthWithSecurity(JNIEnv *env, jclass clazz) {
    return BearMundo::validateKeyAuthWithSecurity();
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_isMemoryOperationSecure(JNIEnv *env, jclass clazz) {
    return BearMundo::isMemoryOperationSecure();
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_isESPOperationSecure(JNIEnv *env, jclass clazz) {
    return BearMundo::isESPOperationSecure();
}

// ========================================
// CONTAINER MANAGEMENT FUNCTIONS
// ========================================

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_initializeContainerManager(JNIEnv *env, jclass clazz) {
    auto* manager = BearMundo::Container::BearMundoContainerManager::getInstance();
    if (manager) {
        return manager->initialize();
    }
    return false;
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_isContainerManagerInitialized(JNIEnv *env, jclass clazz) {
    auto* manager = BearMundo::Container::BearMundoContainerManager::getInstance();
    if (manager) {
        return manager->isManagerInitialized();
    }
    return false;
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_isRootEnvironment(JNIEnv *env, jclass clazz) {
    auto* manager = BearMundo::Container::BearMundoContainerManager::getInstance();
    if (manager) {
        return manager->isRootEnvironment();
    }
    return false;
}

JNIEXPORT jstring JNICALL
Java_com_bearmod_security_BearMundoSecurity_createSecureContainer(JNIEnv *env, jclass clazz, jint containerType) {
    auto* manager = BearMundo::Container::BearMundoContainerManager::getInstance();
    if (!manager || !manager->isManagerInitialized()) {
        return env->NewStringUTF("");
    }
    
    BearMundo::Container::ContainerConfiguration config;
    
    switch (containerType) {
        case 0: // Standard
            config = BearMundo::Container::createStandardConfiguration();
            break;
        case 1: // Root
            config = BearMundo::Container::createRootConfiguration();
            break;
        case 2: // Stealth
            config = BearMundo::Container::createStealthConfiguration();
            break;
        default:
            config = BearMundo::Container::createNonRootConfiguration();
            break;
    }
    
    std::string containerId = manager->createContainer(config);
    return env->NewStringUTF(containerId.c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_activateContainer(JNIEnv *env, jclass clazz, jstring containerId) {
    auto* manager = BearMundo::Container::BearMundoContainerManager::getInstance();
    if (!manager) {
        return false;
    }

    const char* idStr = env->GetStringUTFChars(containerId, nullptr);
    bool result = manager->activateContainer(std::string(idStr));
    env->ReleaseStringUTFChars(containerId, idStr);

    return result;
}

JNIEXPORT jstring JNICALL
Java_com_bearmod_security_BearMundoSecurity_getActiveContainerInfo(JNIEnv *env, jclass clazz) {
    auto* manager = BearMundo::Container::BearMundoContainerManager::getInstance();
    if (!manager) {
        return env->NewStringUTF("Container manager not available");
    }
    
    auto* activeContainer = manager->getActiveContainer();
    if (!activeContainer) {
        return env->NewStringUTF("No active container");
    }
    
    std::string info = "Container ID: " + activeContainer->containerId +
                      ", Type: " + std::to_string(static_cast<int>(activeContainer->config.type)) +
                      ", Security Level: " + std::to_string(static_cast<int>(activeContainer->config.securityLevel)) +
                      ", Environment: " + std::to_string(static_cast<int>(activeContainer->detectedEnvironment));
    
    return env->NewStringUTF(info.c_str());
}

JNIEXPORT jint JNICALL
Java_com_bearmod_security_BearMundoSecurity_getContainerCount(JNIEnv *env, jclass clazz) {
    auto* manager = BearMundo::Container::BearMundoContainerManager::getInstance();
    if (manager) {
        return static_cast<jint>(manager->getContainerCount());
    }
    return 0;
}

// ========================================
// DETECTION FUNCTIONS
// ========================================

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_detectFridaFramework(JNIEnv *env, jclass clazz) {
    return BearMundo::detectFridaFramework();
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_detectAdvancedDebugging(JNIEnv *env, jclass clazz) {
    return BearMundo::detectAdvancedDebugging();
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_detectRootWithEvasion(JNIEnv *env, jclass clazz) {
    return BearMundo::detectRootWithEvasion();
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_BearMundoSecurity_detectEmulatorEnvironment(JNIEnv *env, jclass clazz) {
    return BearMundo::detectEmulatorEnvironment();
}

// ========================================
// UTILITY FUNCTIONS
// ========================================

JNIEXPORT jstring JNICALL
Java_com_bearmod_security_BearMundoSecurity_generateRandomStackName(JNIEnv *env, jclass clazz) {
    std::string name = BearMundo::generateRandomStackName();
    return env->NewStringUTF(name.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_bearmod_security_BearMundoSecurity_generateObfuscatedFunctionName(JNIEnv *env, jclass clazz) {
    std::string name = BearMundo::generateObfuscatedFunctionName();
    return env->NewStringUTF(name.c_str());
}

JNIEXPORT void JNICALL
Java_com_bearmod_security_BearMundoSecurity_randomDelay(JNIEnv *env, jclass clazz) {
    BearMundo::randomDelay();
}

JNIEXPORT void JNICALL
Java_com_bearmod_security_BearMundoSecurity_createDecoyOperations(JNIEnv *env, jclass clazz) {
    BearMundo::createDecoyOperations();
}

} // extern "C"
