#ifndef BEARMUNDO_MEMORY_PROTECTION_H
#define BEARMUNDO_MEMORY_PROTECTION_H

#include <string>
#include <vector>
#include <chrono>
#include <atomic>
#include <mutex>

namespace bearmundo {
namespace security {

class MemoryProtection {
public:
    MemoryProtection();
    ~MemoryProtection();

    // Core functionality
    bool initialize();
    void cleanup();
    
    // Memory protection operations
    bool protectRegion(void* address, size_t size);
    bool unprotectRegion(void* address, size_t size);
    bool isRegionProtected(void* address) const;
    
    // Status
    bool isInitialized() const;
    std::string getLastError() const;

private:
    // Prevent copying
    MemoryProtection(const MemoryProtection&) = delete;
    MemoryProtection& operator=(const MemoryProtection&) = delete;

    // Internal state
    std::atomic<bool> initialized_{false};
    std::string last_error_;
    
    // Memory region tracking
    struct MemoryRegion {
        void* address;
        size_t size;
        bool is_protected;
        std::chrono::system_clock::time_point protection_time;
    };
    std::vector<MemoryRegion> protected_regions_;
    
    // Internal utilities
    bool setupMemoryProtection();
    bool enableASLR();
    bool protectCriticalRegions();
    void setLastError(const std::string& error);
};

} // namespace security
} // namespace bearmundo

#endif // BEARMUNDO_MEMORY_PROTECTION_H 