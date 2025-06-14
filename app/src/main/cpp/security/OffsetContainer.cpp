#include "OffsetContainer.h"
#include <android/log.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/signal.h>
#include <linux/elf.h>
#include <linux/version.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/system_properties.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <json/json.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <curl/curl.h>

#define LOG_TAG "OffsetContainer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

using namespace std;

OffsetContainer* OffsetContainer::instance = nullptr;
mutex OffsetContainer::instanceMutex;

OffsetContainer::OffsetContainer() : isInitialized(false) {
    initializeEncryption();
}

OffsetContainer* OffsetContainer::getInstance() {
    lock_guard<mutex> lock(instanceMutex);
    if (!instance) {
        instance = new OffsetContainer();
    }
    return instance;
}

void OffsetContainer::initializeEncryption() {
    // Generate encryption key
    encryptionKey.resize(32);
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, encryptionKey.data(), encryptionKey.size());
        close(fd);
    }
}

uint32_t OffsetContainer::calculateChecksum(uint64_t value) {
    uint32_t checksum = 0;
    uint8_t* bytes = (uint8_t*)&value;
    for (size_t i = 0; i < sizeof(value); i++) {
        checksum = (checksum << 8) | bytes[i];
    }
    return checksum;
}

string OffsetContainer::signOffset(const string& name, uint64_t value) {
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLen;
    
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, encryptionKey.data(), encryptionKey.size(), EVP_sha256(), nullptr);
    HMAC_Update(ctx, (unsigned char*)name.c_str(), name.length());
    HMAC_Update(ctx, (unsigned char*)&value, sizeof(value));
    HMAC_Final(ctx, hmac, &hmacLen);
    HMAC_CTX_free(ctx);
    
    return string((char*)hmac, hmacLen);
}

bool OffsetContainer::verifySignature(const string& name, const OffsetEntry& entry) {
    string expectedSignature = signOffset(name, entry.value);
    return expectedSignature == entry.signature;
}

void OffsetContainer::encryptOffset(OffsetEntry& entry) {
    if (!entry.isEncrypted) {
        AES_KEY aesKey;
        AES_set_encrypt_key(encryptionKey.data(), 256, &aesKey);
        
        uint64_t encryptedValue = entry.value;
        AES_encrypt((unsigned char*)&encryptedValue, (unsigned char*)&entry.value, &aesKey);
        entry.isEncrypted = true;
    }
}

void OffsetContainer::decryptOffset(OffsetEntry& entry) {
    if (entry.isEncrypted) {
        AES_KEY aesKey;
        AES_set_decrypt_key(encryptionKey.data(), 256, &aesKey);
        
        uint64_t decryptedValue = entry.value;
        AES_decrypt((unsigned char*)&decryptedValue, (unsigned char*)&entry.value, &aesKey);
        entry.isEncrypted = false;
    }
}

bool OffsetContainer::initialize(const vector<uint8_t>& key) {
    lock_guard<mutex> lock(offsetMutex);
    if (!isInitialized) {
        encryptionKey = key;
        isInitialized = true;
        return true;
    }
    return false;
}

bool OffsetContainer::addOffset(const string& name, uint64_t value, bool encrypt) {
    lock_guard<mutex> lock(offsetMutex);
    if (!isInitialized) return false;
    
    OffsetEntry entry;
    entry.value = value;
    entry.checksum = calculateChecksum(value);
    entry.isEncrypted = false;
    entry.signature = signOffset(name, value);
    
    if (encrypt) {
        encryptOffset(entry);
    }
    
    offsets[name] = entry;
    return true;
}

bool OffsetContainer::updateOffset(const string& name, uint64_t value) {
    lock_guard<mutex> lock(offsetMutex);
    if (!isInitialized || offsets.find(name) == offsets.end()) return false;
    
    OffsetEntry& entry = offsets[name];
    if (entry.isEncrypted) {
        decryptOffset(entry);
    }
    
    entry.value = value;
    entry.checksum = calculateChecksum(value);
    entry.signature = signOffset(name, value);
    
    if (entry.isEncrypted) {
        encryptOffset(entry);
    }
    
    return true;
}

uint64_t OffsetContainer::getOffset(const string& name) {
    lock_guard<mutex> lock(offsetMutex);
    if (!isInitialized || offsets.find(name) == offsets.end()) return 0;
    
    OffsetEntry& entry = offsets[name];
    if (entry.isEncrypted) {
        decryptOffset(entry);
    }
    
    if (!verifySignature(name, entry)) {
        LOGE("Offset integrity check failed for %s", name.c_str());
        return 0;
    }
    
    return entry.value;
}

bool OffsetContainer::verifyIntegrity() {
    lock_guard<mutex> lock(offsetMutex);
    if (!isInitialized) return false;
    
    for (const auto& pair : offsets) {
        if (!verifySignature(pair.first, pair.second)) {
            return false;
        }
    }
    return true;
}

void OffsetContainer::clear() {
    lock_guard<mutex> lock(offsetMutex);
    offsets.clear();
    isInitialized = false;
}

bool OffsetContainer::enableKernelProtection() {
    struct sock_filter filter[] = {
        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        // Check for ptrace
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ptrace, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        
        // Check for process_vm_readv/writev
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_process_vm_readv, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_process_vm_writev, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        
        // Default allow
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter
    };

    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0;
}

bool OffsetContainer::disableKernelProtection() {
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED) == 0;
}

bool OffsetContainer::isKernelProtected() {
    int mode;
    return prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == SECCOMP_MODE_FILTER;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool OffsetContainer::updateFromServer(const string& serverUrl, const string& authToken) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    
    string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + authToken).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, serverUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) return false;
    
    return validateRemoteUpdate(response);
}

bool OffsetContainer::validateRemoteUpdate(const string& updateData) {
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(updateData, root)) return false;
    
    lock_guard<mutex> lock(offsetMutex);
    for (const auto& offset : root["offsets"]) {
        string name = offset["name"].asString();
        uint64_t value = offset["value"].asUInt64();
        string signature = offset["signature"].asString();
        
        if (signature != signOffset(name, value)) {
            return false;
        }
        
        addOffset(name, value, true);
    }
    
    return true;
}

OffsetContainer::~OffsetContainer() {
    clear();
} 