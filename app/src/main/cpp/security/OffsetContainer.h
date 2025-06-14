#ifndef BEARMUNDO_OFFSET_CONTAINER_H
#define BEARMUNDO_OFFSET_CONTAINER_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <cstdint>

class OffsetContainer {
private:
    static OffsetContainer* instance;
    static std::mutex instanceMutex;
    
    struct OffsetEntry {
        uint64_t value;
        uint32_t checksum;
        bool isEncrypted;
        std::string signature;
    };
    
    std::map<std::string, OffsetEntry> offsets;
    std::mutex offsetMutex;
    std::vector<uint8_t> encryptionKey;
    bool isInitialized;
    
    OffsetContainer();
    void initializeEncryption();
    uint32_t calculateChecksum(uint64_t value);
    std::string signOffset(const std::string& name, uint64_t value);
    bool verifySignature(const std::string& name, const OffsetEntry& entry);
    void encryptOffset(OffsetEntry& entry);
    void decryptOffset(OffsetEntry& entry);
    
public:
    static OffsetContainer* getInstance();
    
    bool initialize(const std::vector<uint8_t>& key);
    bool addOffset(const std::string& name, uint64_t value, bool encrypt = true);
    bool updateOffset(const std::string& name, uint64_t value);
    uint64_t getOffset(const std::string& name);
    bool verifyIntegrity();
    void clear();
    
    // Kernel-level protection methods
    bool enableKernelProtection();
    bool disableKernelProtection();
    bool isKernelProtected();
    
    // Remote update methods
    bool updateFromServer(const std::string& serverUrl, const std::string& authToken);
    bool validateRemoteUpdate(const std::string& updateData);
    
    ~OffsetContainer();
};

#endif // BEARMUNDO_OFFSET_CONTAINER_H 