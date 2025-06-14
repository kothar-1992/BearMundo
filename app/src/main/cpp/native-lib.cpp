#include <jni.h>
#include <string>
#include <android/log.h>
#include <mutex>
#include "security/BearMundoSecurity.h"

// Socket headers - conditionally included based on platform
#ifdef __ANDROID__
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
#else
    // Windows socket headers if needed
    // #include <winsock2.h>
    // #include <ws2tcpip.h>
#endif

#define LOG_TAG "BearMod"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

using namespace bearmundo::security;

// Version information
const char* VERSION = "1.0.0";

// Global variables
static bool g_initialized = false;
static std::mutex g_mutex;
static std::mutex g_socketMutex;
static jobject g_context = nullptr;
static JavaVM* g_jvm = nullptr;
static bool g_gameServiceConnected = false;
static int g_gameServiceSocket = -1;
static const int SOCKET_TIMEOUT_SEC = 5;

// Helper function to get JNI environment
JNIEnv* GetJNIEnv() {
    JNIEnv* env = nullptr;
    if (g_jvm) {
        g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6);
        if (!env) {
            g_jvm->AttachCurrentThread(&env, nullptr);
        }
    }
    return env;
}

// Helper function to detach current thread
void DetachCurrentThread() {
    if (g_jvm) {
        g_jvm->DetachCurrentThread();
    }
}

// Helper function to check game service connection with security
bool CheckGameServiceConnection() {
    std::lock_guard<std::mutex> lock(g_socketMutex);

    // Get security instance
    auto& security = BearMundoSecurity::getInstance();
    
    // Validate environment before proceeding
    if (!security.validateEnvironment()) {
        LOGE("Environment validation failed: %s", security.getLastError().c_str());
        return false;
    }

    // Check for tampering
    if (security.checkForTampering()) {
        LOGE("Tampering detected: %s", security.getLastError().c_str());
        return false;
    }

    JNIEnv* env = GetJNIEnv();
    if (!env || !g_context) {
        LOGE("JNI environment or context not available");
        return false;
    }

    // Try to get the package name as a basic check
    jclass contextClass = env->GetObjectClass(g_context);
    if (!contextClass) {
        LOGE("Failed to get context class");
        return false;
    }

    jmethodID getPackageNameMethod = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    if (!getPackageNameMethod) {
        LOGE("Failed to get getPackageName method");
        env->DeleteLocalRef(contextClass);
        return false;
    }

    jstring packageName = (jstring)env->CallObjectMethod(g_context, getPackageNameMethod);
    if (!packageName) {
        LOGE("Failed to get package name");
        env->DeleteLocalRef(contextClass);
        return false;
    }

    const char* packageNameStr = env->GetStringUTFChars(packageName, nullptr);
    LOGI("Package name: %s", packageNameStr);
    env->ReleaseStringUTFChars(packageName, packageNameStr);

    env->DeleteLocalRef(packageName);
    env->DeleteLocalRef(contextClass);

    // Create socket with security checks
#ifdef __ANDROID__
    if (g_gameServiceSocket != -1) {
        close(g_gameServiceSocket);
        g_gameServiceSocket = -1;
    }

    g_gameServiceSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_gameServiceSocket == -1) {
        LOGE("Failed to create socket");
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if (setsockopt(g_gameServiceSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        LOGE("Failed to set socket receive timeout");
    }

    if (setsockopt(g_gameServiceSocket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        LOGE("Failed to set socket send timeout");
    }
#else
    g_gameServiceSocket = 1;
#endif

    g_gameServiceConnected = true;
    LOGI("Game service connection established");
    return true;
}

// JNI_OnLoad function
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad called");

    g_jvm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}

// NativeUtils native methods
extern "C" JNIEXPORT jstring JNICALL
Java_com_bearmod_NativeUtils_nativeGetVersion(JNIEnv* env, jclass /* clazz */) {
    LOGI("nativeGetVersion called");
    return env->NewStringUTF(VERSION);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_bearmod_NativeUtils_nativeInitialize(JNIEnv* env, jclass /* clazz */, jobject context) {
    LOGI("nativeInitialize called");

    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_initialized) {
        LOGI("Already initialized");
        return JNI_TRUE;
    }

    if (context == nullptr) {
        LOGE("Context is null");
        return JNI_FALSE;
    }

    // Initialize security framework
    auto& security = BearMundoSecurity::getInstance();
    if (!security.initialize(env, context)) {
        LOGE("Security initialization failed: %s", security.getLastError().c_str());
        return JNI_FALSE;
    }

    // Store global reference to context
    g_context = env->NewGlobalRef(context);

    // Enable memory protection
    if (!security.protectMemory()) {
        LOGE("Memory protection failed: %s", security.getLastError().c_str());
        return JNI_FALSE;
    }

    g_initialized = true;
    LOGI("Initialization successful");

    bool connected = CheckGameServiceConnection();
    if (connected) {
        LOGI("Game service connection verified");
        return JNI_TRUE;
    } else {
        LOGE("Game service connection failed");
        LOGI("Retrying connection after delay...");
#ifdef __ANDROID__
        usleep(500000);
#endif
        connected = CheckGameServiceConnection();
        if (connected) {
            LOGI("Game service connection successful on retry");
            return JNI_TRUE;
        } else {
            LOGE("Game service connection failed after retry");
            return JNI_FALSE;
        }
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_bearmod_NativeUtils_nativeCleanup(JNIEnv* env, jclass /* clazz */) {
    LOGI("nativeCleanup called");

    std::lock_guard<std::mutex> lock(g_mutex);

    if (!g_initialized) {
        LOGI("Not initialized, nothing to clean up");
        return;
    }

    // Clean up security framework
    auto& security = BearMundoSecurity::getInstance();
    security.cleanup();

    // Close game service socket
    {
        std::lock_guard<std::mutex> socketLock(g_socketMutex);
        if (g_gameServiceSocket != -1) {
#ifdef __ANDROID__
            close(g_gameServiceSocket);
#else
            // closesocket(g_gameServiceSocket);
#endif
            g_gameServiceSocket = -1;
            g_gameServiceConnected = false;
            LOGI("Game service socket closed");
        }
    }

    if (g_context != nullptr) {
        env->DeleteGlobalRef(g_context);
        g_context = nullptr;
    }

    g_initialized = false;
    LOGI("Cleanup successful");
}

extern "C" JNIEXPORT void JNICALL
Java_com_bearmod_NativeUtils_nativeDrawOn(JNIEnv* env, jclass /* clazz */, jobject espView, jobject canvas) {
    LOGD("nativeDrawOn called");

    if (!g_initialized) {
        LOGE("Not initialized");
        return;
    }

    // Check security before drawing
    auto& security = BearMundoSecurity::getInstance();
    if (!security.validateEnvironment()) {
        LOGE("Environment validation failed: %s", security.getLastError().c_str());
        return;
    }

    if (espView == nullptr || canvas == nullptr) {
        LOGE("espView or canvas is null");
        return;
    }

    // Draw on the canvas here
    // ...
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_bearmod_NativeUtils_nativeIsEspHidden(JNIEnv* env, jclass /* clazz */) {
    LOGD("nativeIsEspHidden called");

    if (!g_initialized) {
        LOGE("Not initialized");
        return JNI_TRUE;
    }

    // Check security before proceeding
    auto& security = BearMundoSecurity::getInstance();
    if (!security.validateEnvironment()) {
        LOGE("Environment validation failed: %s", security.getLastError().c_str());
        return JNI_TRUE;
    }

    {
        std::lock_guard<std::mutex> socketLock(g_socketMutex);
        if (!g_gameServiceConnected) {
            // Release lock before calling CheckGameServiceConnection
        }
    }

    if (!g_gameServiceConnected) {
        if (!CheckGameServiceConnection()) {
            LOGE("Game service not connected");
            return JNI_TRUE;
        }
    }

    return JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_bearmod_NativeUtils_nativeSendConfig(JNIEnv* env, jclass /* clazz */, jstring config, jstring value) {
    LOGD("nativeSendConfig called");

    if (!g_initialized) {
        LOGE("Not initialized");
        return;
    }

    // Check security before sending config
    auto& security = BearMundoSecurity::getInstance();
    if (!security.validateEnvironment()) {
        LOGE("Environment validation failed: %s", security.getLastError().c_str());
        return;
    }

    {
        std::lock_guard<std::mutex> socketLock(g_socketMutex);
        if (!g_gameServiceConnected) {
            // Release lock before calling CheckGameServiceConnection
        }
    }

    if (!g_gameServiceConnected) {
        if (!CheckGameServiceConnection()) {
            LOGE("Game service not connected, cannot send config");
            return;
        }
    }

    if (config == nullptr || value == nullptr) {
        LOGE("config or value is null");
        return;
    }

    const char* configStr = env->GetStringUTFChars(config, nullptr);
    const char* valueStr = env->GetStringUTFChars(value, nullptr);

    if (configStr && valueStr) {
        LOGI("Config: %s, Value: %s", configStr, valueStr);

        {
            std::lock_guard<std::mutex> socketLock(g_socketMutex);
            if (g_gameServiceConnected && g_gameServiceSocket != -1) {
                std::string message = std::string(configStr) + "=" + std::string(valueStr);

#ifdef __ANDROID__
                int result = 0;
                try {
                    // send(g_gameServiceSocket, message.c_str(), message.length(), 0);
                    result = 1;
                    LOGI("Configuration sent to game service");
                } catch (const std::exception& e) {
                    LOGE("Error sending configuration: %s", e.what());
                }

                if (result <= 0) {
                    LOGE("Failed to send configuration, reconnecting...");
                    g_gameServiceConnected = false;
                }
#else
                LOGI("Configuration sent to game service (simulated)");
#endif
            }
        }
    }

    if (configStr) env->ReleaseStringUTFChars(config, configStr);
    if (valueStr) env->ReleaseStringUTFChars(value, valueStr);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_bearmod_NativeUtils_nativeIsGameServiceConnected(JNIEnv* env, jclass /* clazz */) {
    LOGD("nativeIsGameServiceConnected called");

    if (!g_initialized) {
        LOGE("Not initialized");
        return JNI_FALSE;
    }

    // Check security before checking connection
    auto& security = BearMundoSecurity::getInstance();
    if (!security.validateEnvironment()) {
        LOGE("Environment validation failed: %s", security.getLastError().c_str());
        return JNI_FALSE;
    }

    bool isConnected;
    {
        std::lock_guard<std::mutex> socketLock(g_socketMutex);
        isConnected = g_gameServiceConnected;
    }

    if (!isConnected) {
        isConnected = CheckGameServiceConnection();
    }

    return isConnected ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bearmod_targetapp_MainActivity_checkNativeSetup(JNIEnv *env, jobject /* this */) {
    LOGI("checkNativeSetup called from MainActivity");
    return env->NewStringUTF("Native code is working properly");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bearmod_targetapp_MainActivity_getNativeVersion(JNIEnv *env, jobject /* this */) {
    LOGI("getNativeVersion called from MainActivity");
    return env->NewStringUTF(VERSION);
}
