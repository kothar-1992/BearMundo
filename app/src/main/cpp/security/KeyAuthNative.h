#pragma once

#include <android/log.h>
#include <jni.h>
#include <string>
#include <vector>
#include <memory>
#include <curl/curl.h>

// Obfuscated strings
constexpr auto OBF_APP_ID = "\x42\x65\x61\x72\x4d\x6f\x64\x53\x65\x63\x75\x72\x69\x74\x79";
constexpr auto OBF_APP_SECRET = "\x42\x65\x61\x72\x4d\x6f\x64\x53\x65\x63\x75\x72\x65\x4b\x65\x79";
constexpr auto OBF_API_URL = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6b\x65\x79\x61\x75\x74\x68\x2e\x77\x69\x6e\x2f\x61\x70\x69\x2f\x73\x65\x6c\x6c\x65\x72\x2f";

// Whitelisted package signatures (obfuscated)
const std::vector<std::string> WHITELISTED_SIGNATURES = {
    "\x42\x65\x61\x72\x4d\x6f\x64\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x31",
    "\x42\x65\x61\x72\x4d\x6f\x64\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x32"
};

class KeyAuthNative {
private:
    static KeyAuthNative* instance;
    std::string sessionId;
    bool isInitialized;
    
    // Obfuscated validation methods
    bool validatePackageSignature(JNIEnv* env, jobject context);
    bool validateDeviceIntegrity();
    std::string encryptData(const std::string& data);
    std::string decryptData(const std::string& encrypted);
    
    // Prevent direct instantiation
    KeyAuthNative();
    
public:
    static KeyAuthNative* getInstance();
    ~KeyAuthNative();
    
    // Core authentication methods
    bool initialize(JNIEnv* env, jobject context);
    bool authenticate(const std::string& licenseKey, JNIEnv* env, jobject context);
    bool validateSession();
    void logout();
    
    // Security validation
    bool isPackageValid(JNIEnv* env, jobject context);
    bool isDeviceSecure();
    
    // Cleanup
    void cleanup();
}; 