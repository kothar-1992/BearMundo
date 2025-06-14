#include <jni.h>
#include <string>
#include <android/log.h>
#include "security/BearMundoSecurity.h"

#define TAG "BearModSecurity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

using namespace bearmundo::security;

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_bearmod_MainActivity_stringFromJNI(JNIEnv *env, jobject /* this */) {
    std::string hello = "Hello from BearMod Security";
    LOGI("Native code executed: %s", hello.c_str());
    return env->NewStringUTF(hello.c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_MainActivity_initializeNative(JNIEnv *env, jobject /* this */) {
    LOGI("Native initialization called");
    try {
        // Initialize security framework
        auto& security = BearMundoSecurity::getInstance();
        if (!security.initialize(env, nullptr)) {
            LOGE("Security initialization failed: %s", security.getLastError().c_str());
            return JNI_FALSE;
        }

        // Validate environment
        if (!security.validateEnvironment()) {
            LOGE("Environment validation failed: %s", security.getLastError().c_str());
            return JNI_FALSE;
        }

        // Check integrity
        if (!security.checkIntegrity()) {
            LOGE("Integrity check failed: %s", security.getLastError().c_str());
            return JNI_FALSE;
        }

        // Enable memory protection
        if (!security.protectMemory()) {
            LOGE("Memory protection failed: %s", security.getLastError().c_str());
            return JNI_FALSE;
        }

        LOGI("Native initialization successful");
        return JNI_TRUE;
    } catch (const std::exception& e) {
        LOGE("Native initialization failed: %s", e.what());
        return JNI_FALSE;
    }
}

JNIEXPORT void JNICALL
Java_com_bearmod_MainActivity_cleanupNative(JNIEnv *env, jobject /* this */) {
    LOGI("Native cleanup called");
    try {
        auto& security = BearMundoSecurity::getInstance();
        security.cleanup();
        LOGI("Native cleanup successful");
    } catch (const std::exception& e) {
        LOGE("Native cleanup failed: %s", e.what());
    }
}

} // extern "C"
