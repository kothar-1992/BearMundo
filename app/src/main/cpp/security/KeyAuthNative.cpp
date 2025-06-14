#include "KeyAuthNative.h"
#include <android/log.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/prctl.h>
#include <curl/curl.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#define LOG_TAG "KeyAuthNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Obfuscated strings
constexpr auto OBF_APP_ID = "\x42\x65\x61\x72\x4d\x6f\x64\x53\x65\x63\x75\x72\x69\x74\x79";
constexpr auto OBF_APP_SECRET = "\x42\x65\x61\x72\x4d\x6f\x64\x53\x65\x63\x75\x72\x65\x4b\x65\x79";
constexpr auto OBF_API_URL = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6b\x65\x79\x61\x75\x74\x68\x2e\x77\x69\x6e\x2f\x61\x70\x69\x2f\x73\x65\x6c\x6c\x65\x72\x2f";

// Whitelisted package signatures (obfuscated)
const std::vector<std::string> WHITELISTED_SIGNATURES = {
    "\x42\x65\x61\x72\x4d\x6f\x64\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x31",
    "\x42\x65\x61\x72\x4d\x6f\x64\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x32"
};

KeyAuthNative* KeyAuthNative::instance = nullptr;

KeyAuthNative::KeyAuthNative() : isInitialized(false) {
    // Prevent debugging
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_TRACEABLE, 0);
    
    // Initialize curl
    curl_global_init(CURL_GLOBAL_ALL);
}

KeyAuthNative::~KeyAuthNative() {
    curl_global_cleanup();
}

KeyAuthNative* KeyAuthNative::getInstance() {
    if (instance == nullptr) {
        instance = new KeyAuthNative();
    }
    return instance;
}

bool KeyAuthNative::initialize(JNIEnv* env, jobject context) {
    if (isInitialized) return true;
    
    // Validate package signature
    if (!validatePackageSignature(env, context)) {
        LOGE("Invalid package signature");
        return false;
    }
    
    // Validate device integrity
    if (!validateDeviceIntegrity()) {
        LOGE("Device integrity check failed");
        return false;
    }
    
    isInitialized = true;
    return true;
}

bool KeyAuthNative::validatePackageSignature(JNIEnv* env, jobject context) {
    // Get package manager
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject packageManager = env->CallObjectMethod(context, getPackageManager);
    
    // Get package name
    jmethodID getPackageName = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    jstring packageName = (jstring)env->CallObjectMethod(context, getPackageName);
    
    // Get package info
    jclass packageManagerClass = env->GetObjectClass(packageManager);
    jmethodID getPackageInfo = env->GetMethodID(packageManagerClass, "getPackageInfo", 
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject packageInfo = env->CallObjectMethod(packageManager, getPackageInfo, packageName, 64);
    
    // Get signatures
    jclass packageInfoClass = env->GetObjectClass(packageInfo);
    jfieldID signaturesField = env->GetFieldID(packageInfoClass, "signatures", "[Landroid/content/pm/Signature;");
    jobjectArray signatures = (jobjectArray)env->GetObjectField(packageInfo, signaturesField);
    
    // Check signatures against whitelist
    jsize length = env->GetArrayLength(signatures);
    for (int i = 0; i < length; i++) {
        jobject signature = env->GetObjectArrayElement(signatures, i);
        jclass signatureClass = env->GetObjectClass(signature);
        jmethodID toCharsString = env->GetMethodID(signatureClass, "toCharsString", "()Ljava/lang/String;");
        jstring signatureString = (jstring)env->CallObjectMethod(signature, toCharsString);
        
        const char* sig = env->GetStringUTFChars(signatureString, nullptr);
        std::string sigStr(sig);
        env->ReleaseStringUTFChars(signatureString, sig);
        
        // Check against whitelist
        for (const auto& whitelisted : WHITELISTED_SIGNATURES) {
            if (sigStr == whitelisted) {
                return true;
            }
        }
    }
    
    return false;
}

bool KeyAuthNative::validateDeviceIntegrity() {
    // Check for root
    if (access("/system/xbin/su", F_OK) == 0) return false;
    if (access("/system/bin/su", F_OK) == 0) return false;
    
    // Check for debugger
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) return false;
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    
    // Check for emulator
    char prop[PROP_VALUE_MAX];
    if (__system_property_get("ro.kernel.qemu", prop) > 0) return false;
    if (__system_property_get("ro.hardware", prop) > 0 && strcmp(prop, "goldfish") == 0) return false;
    
    return true;
}

std::string KeyAuthNative::encryptData(const std::string& data) {
    // Initialize encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    // Generate random IV
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
        reinterpret_cast<const unsigned char*>(OBF_APP_SECRET), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Prepare output buffer
    std::vector<unsigned char> outbuf(data.length() + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;
    
    // Encrypt data
    if (EVP_EncryptUpdate(ctx, outbuf.data(), &outlen,
        reinterpret_cast<const unsigned char*>(data.c_str()), data.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, outbuf.data() + outlen, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine IV and encrypted data
    std::string result;
    result.append(reinterpret_cast<char*>(iv), sizeof(iv));
    result.append(reinterpret_cast<char*>(outbuf.data()), outlen);
    
    return result;
}

std::string KeyAuthNative::decryptData(const std::string& encrypted) {
    if (encrypted.length() < 16) return "";
    
    // Extract IV
    unsigned char iv[16];
    memcpy(iv, encrypted.c_str(), 16);
    
    // Initialize decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(OBF_APP_SECRET), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Prepare output buffer
    std::vector<unsigned char> outbuf(encrypted.length() - 16);
    int outlen = 0;
    
    // Decrypt data
    if (EVP_DecryptUpdate(ctx, outbuf.data(), &outlen,
        reinterpret_cast<const unsigned char*>(encrypted.c_str() + 16),
        encrypted.length() - 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    int tmplen = 0;
    if (EVP_DecryptFinal_ex(ctx, outbuf.data() + outlen, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

bool KeyAuthNative::authenticate(const std::string& licenseKey, JNIEnv* env, jobject context) {
    if (!isInitialized) {
        LOGE("KeyAuth not initialized");
        return false;
    }
    
    // Validate package and device again
    if (!isPackageValid(env, context) || !isDeviceSecure()) {
        LOGE("Security validation failed");
        return false;
    }
    
    // Prepare authentication request
    std::stringstream ss;
    ss << "{\"license\":\"" << licenseKey << "\",\"type\":\"auth\"}";
    std::string requestData = ss.str();
    
    // Encrypt request data
    std::string encryptedData = encryptData(requestData);
    if (encryptedData.empty()) {
        LOGE("Failed to encrypt request data");
        return false;
    }
    
    // Initialize curl
    CURL* curl = curl_easy_init();
    if (!curl) {
        LOGE("Failed to initialize curl");
        return false;
    }
    
    // Set up curl options
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, OBF_API_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encryptedData.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, encryptedData.length());
    
    // Response handling
    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        LOGE("Curl request failed: %s", curl_easy_strerror(res));
        return false;
    }
    
    // Decrypt and parse response
    std::string decryptedResponse = decryptData(response);
    if (decryptedResponse.empty()) {
        LOGE("Failed to decrypt response");
        return false;
    }
    
    // Parse response (simplified for example)
    if (decryptedResponse.find("\"success\":true") != std::string::npos) {
        sessionId = "session_" + licenseKey;
        return true;
    }
    
    return false;
}

bool KeyAuthNative::validateSession() {
    if (sessionId.empty()) return false;
    
    // Implement session validation logic here
    // This could involve checking a local cache or making a lightweight API call
    return true;
}

void KeyAuthNative::logout() {
    sessionId.clear();
}

bool KeyAuthNative::isPackageValid(JNIEnv* env, jobject context) {
    return validatePackageSignature(env, context);
}

bool KeyAuthNative::isDeviceSecure() {
    return validateDeviceIntegrity();
}

void KeyAuthNative::cleanup() {
    if (instance != nullptr) {
        delete instance;
        instance = nullptr;
    }
} 