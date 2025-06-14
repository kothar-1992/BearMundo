#include "MemoryProtection.h"
#include <android/log.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>

#define TAG "MemoryProtection"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

namespace bearmundo {
namespace security {

MemoryProtection::MemoryProtection() {
    LOGI("MemoryProtection constructor called");
}

MemoryProtection::~MemoryProtection() {
    cleanup();
    LOGI("MemoryProtection destructor called");
}

bool MemoryProtection::initialize() {
    try {
        // Set up memory protection
        if (!setupMemoryProtection()) {
            setLastError("Failed to set up memory protection");
            return false;
        }

        // Enable ASLR
        if (!enableASLR()) {
            setLastError("Failed to enable ASLR");
            return false;
        }

        // Protect critical memory regions
        if (!protectCriticalRegions()) {
            setLastError("Failed to protect critical regions");
            return false;
        }

        initialized_ = true;
        LOGI("Memory protection initialized successfully");
        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("Initialization failed: ") + e.what());
        return false;
    }
}

void MemoryProtection::cleanup() {
    if (!initialized_) {
        return;
    }

    try {
        // Unprotect all memory regions
        for (auto& region : protected_regions_) {
            if (region.is_protected) {
                unprotectRegion(region.address, region.size);
            }
        }
        protected_regions_.clear();

        initialized_ = false;
        LOGI("Memory protection cleanup completed");
    } catch (const std::exception& e) {
        LOGE("Cleanup failed: %s", e.what());
    }
}

bool MemoryProtection::protectRegion(void* address, size_t size) {
    if (!address || size == 0) {
        setLastError("Invalid memory region");
        return false;
    }

    try {
        // Align address to page boundary
        void* alignedAddr = (void*)((uintptr_t)address & ~(getpagesize() - 1));
        size_t alignedSize = ((size + getpagesize() - 1) & ~(getpagesize() - 1));

        // Set memory protection
        if (mprotect(alignedAddr, alignedSize, PROT_READ) != 0) {
            setLastError("Failed to set memory protection");
            return false;
        }

        // Track protected region
        MemoryRegion region;
        region.address = alignedAddr;
        region.size = alignedSize;
        region.is_protected = true;
        region.protection_time = std::chrono::system_clock::now();
        protected_regions_.push_back(region);

        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("Memory protection failed: ") + e.what());
        return false;
    }
}

bool MemoryProtection::unprotectRegion(void* address, size_t size) {
    if (!address || size == 0) {
        setLastError("Invalid memory region");
        return false;
    }

    try {
        // Find and remove region from tracking
        auto it = std::find_if(protected_regions_.begin(), protected_regions_.end(),
            [address](const MemoryRegion& region) {
                return region.address == address;
            });

        if (it == protected_regions_.end()) {
            setLastError("Memory region not found");
            return false;
        }

        // Remove protection
        if (mprotect(address, size, PROT_READ | PROT_WRITE) != 0) {
            setLastError("Failed to remove memory protection");
            return false;
        }

        protected_regions_.erase(it);
        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("Memory unprotection failed: ") + e.what());
        return false;
    }
}

bool MemoryProtection::isRegionProtected(void* address) const {
    if (!address) {
        return false;
    }

    try {
        auto it = std::find_if(protected_regions_.begin(), protected_regions_.end(),
            [address](const MemoryRegion& region) {
                return region.address == address;
            });

        return it != protected_regions_.end() && it->is_protected;
    } catch (const std::exception& e) {
        LOGE("Memory protection check failed: %s", e.what());
        return false;
    }
}

bool MemoryProtection::setupMemoryProtection() {
    try {
        // Set up memory protection flags
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            setLastError("Failed to set NO_NEW_PRIVS");
            return false;
        }

        // Enable memory protection
        if (prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, 0, 0, 0) != 0) {
            setLastError("Failed to set memory protection");
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("Memory protection setup failed: ") + e.what());
        return false;
    }
}

bool MemoryProtection::enableASLR() {
    try {
        // Enable ASLR
        if (prctl(PR_SET_MM, PR_SET_MM_RANDOMIZE, 1, 0, 0) != 0) {
            setLastError("Failed to enable ASLR");
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("ASLR enablement failed: ") + e.what());
        return false;
    }
}

bool MemoryProtection::protectCriticalRegions() {
    try {
        // Protect the memory protection instance
        void* instanceAddr = this;
        if (!protectRegion(instanceAddr, sizeof(MemoryProtection))) {
            setLastError("Failed to protect memory protection instance");
            return false;
        }

        // Protect the protected regions vector
        void* regionsAddr = &protected_regions_;
        if (!protectRegion(regionsAddr, sizeof(protected_regions_))) {
            setLastError("Failed to protect regions vector");
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("Critical region protection failed: ") + e.what());
        return false;
    }
}

void MemoryProtection::setLastError(const std::string& error) {
    last_error_ = error;
    LOGE("%s", error.c_str());
}

std::string MemoryProtection::getLastError() const {
    return last_error_;
}

bool MemoryProtection::isInitialized() const {
    return initialized_;
}

} // namespace security
} // namespace bearmundo 