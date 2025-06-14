#include "BearMundoSecurity.h"
#include <android/log.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/system_properties.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_cthelper.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>
#include <linux/netfilter/nfnetlink_ctexpect.h>
#include <linux/netfilter/nfnetlink_acct.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_cthelper.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>
#include <linux/netfilter/nfnetlink_ctexpect.h>
#include <linux/netfilter/nfnetlink_acct.h>

#define TAG "BearMundoSecurity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

namespace bearmundo {
namespace security {

BearMundoSecurity& BearMundoSecurity::getInstance() {
    static BearMundoSecurity instance;
    return instance;
}

BearMundoSecurity::BearMundoSecurity() 
    : gen_(rd_())
    , dis_(0, 1000000) {
    LOGI("BearMundoSecurity constructor called");
}

BearMundoSecurity::~BearMundoSecurity() {
    cleanup();
    LOGI("BearMundoSecurity destructor called");
}

bool BearMundoSecurity::initialize(JNIEnv* env, jobject context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        LOGI("Already initialized");
        return true;
    }

    try {
        // Initialize components
        if (!initializeComponents()) {
            setLastError("Failed to initialize components");
            return false;
        }

        // Perform initial security checks
        if (!performSecurityChecks()) {
            setLastError("Failed security checks");
            return false;
        }

        // Set up memory protection
        if (!protectMemory()) {
            setLastError("Failed to set up memory protection");
            return false;
        }

        initialized_ = true;
        secure_ = true;
        LOGI("Initialization successful");
        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("Initialization failed: ") + e.what());
        return false;
    }
}

void BearMundoSecurity::cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return;
    }

    try {
        // Stop secure thread if running
        if (thread_running_) {
            thread_running_ = false;
            cv_.notify_all();
            if (secure_thread_.joinable()) {
                secure_thread_.join();
            }
        }

        // Clean up components
        cleanupComponents();

        // Unprotect memory regions
        for (auto& region : protected_regions_) {
            if (region.is_protected) {
                unprotectMemoryRegion(region.address);
            }
        }
        protected_regions_.clear();

        initialized_ = false;
        secure_ = false;
        LOGI("Cleanup completed");
    } catch (const std::exception& e) {
        LOGE("Cleanup failed: %s", e.what());
    }
}

bool BearMundoSecurity::validateEnvironment() {
    if (!initialized_) {
        setLastError("Not initialized");
        return false;
    }

    try {
        // Check for debugger
        if (checkForDebugger()) {
            setLastError("Debugger detected");
            return false;
        }

        // Check for emulator
        if (checkForEmulator()) {
            setLastError("Emulator detected");
            return false;
        }

        // Check for root
        if (checkForRoot()) {
            setLastError("Root detected");
            return false;
        }

        // Check for tampering
        if (checkForTampering()) {
            setLastError("Tampering detected");
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("Environment validation failed: ") + e.what());
        return false;
    }
}

bool BearMundoSecurity::checkForDebugger() {
    // Check for ptrace
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        return true;
    }
    ptrace(PTRACE_TRACEME, 0, 0, 0);

    // Check for debugger process
    char buf[512];
    snprintf(buf, sizeof(buf), "/proc/%d/status", getpid());
    FILE* fp = fopen(buf, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "TracerPid:") && line[10] != '0') {
                fclose(fp);
                return true;
            }
        }
        fclose(fp);
    }

    return false;
}

bool BearMundoSecurity::checkForEmulator() {
    char prop[PROP_VALUE_MAX];
    
    // Check for common emulator properties
    if (__system_property_get("ro.kernel.qemu", prop) > 0) {
        return true;
    }
    if (__system_property_get("ro.hardware", prop) > 0) {
        if (strstr(prop, "goldfish") || strstr(prop, "ranchu")) {
            return true;
        }
    }
    if (__system_property_get("ro.product.cpu.abi", prop) > 0) {
        if (strstr(prop, "x86") || strstr(prop, "x86_64")) {
            return true;
        }
    }

    return false;
}

bool BearMundoSecurity::checkForRoot() {
    // Check for common root files
    const char* rootPaths[] = {
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/system/su",
        "/system/bin/.ext/su",
        "/system/xbin/mu"
    };

    for (const char* path : rootPaths) {
        if (access(path, F_OK) == 0) {
            return true;
        }
    }

    // Check for root via which command
    FILE* fp = popen("which su", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp)) {
            pclose(fp);
            return true;
        }
        pclose(fp);
    }

    return false;
}

bool BearMundoSecurity::checkForTampering() {
    // Check for modified system properties
    char prop[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.type", prop) > 0) {
        if (strcmp(prop, "user") != 0) {
            return true;
        }
    }

    // Check for modified system files
    const char* systemFiles[] = {
        "/system/build.prop",
        "/system/framework/framework.jar",
        "/system/framework/services.jar"
    };

    for (const char* file : systemFiles) {
        struct stat st;
        if (stat(file, &st) == 0) {
            // Check file permissions
            if ((st.st_mode & S_IWOTH) != 0) {
                return true;
            }
        }
    }

    return false;
}

bool BearMundoSecurity::protectMemory() {
    if (!initialized_) {
        setLastError("Not initialized");
        return false;
    }

    try {
        // Protect the security instance
        void* instanceAddr = &getInstance();
        if (!protectMemoryRegion(instanceAddr, sizeof(BearMundoSecurity))) {
            setLastError("Failed to protect security instance");
            return false;
        }

        // Protect component memory
        if (stealth_ops_) {
            void* stealthAddr = stealth_ops_.get();
            if (!protectMemoryRegion(stealthAddr, sizeof(StealthOperations))) {
                setLastError("Failed to protect stealth operations");
                return false;
            }
        }

        if (anti_detection_) {
            void* antiDetectAddr = anti_detection_.get();
            if (!protectMemoryRegion(antiDetectAddr, sizeof(AntiDetection))) {
                setLastError("Failed to protect anti-detection");
                return false;
            }
        }

        return true;
    } catch (const std::exception& e) {
        setLastError(std::string("Memory protection failed: ") + e.what());
        return false;
    }
}

bool BearMundoSecurity::protectMemoryRegion(void* address, size_t size) {
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

bool BearMundoSecurity::unprotectMemoryRegion(void* address) {
    if (!address) {
        setLastError("Invalid memory address");
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
        if (mprotect(address, it->size, PROT_READ | PROT_WRITE) != 0) {
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

bool BearMundoSecurity::isMemoryProtected(void* address) {
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

void BearMundoSecurity::setLastError(const std::string& error) {
    last_error_ = error;
    LOGE("%s", error.c_str());
}

std::string BearMundoSecurity::getLastError() const {
    return last_error_;
}

bool BearMundoSecurity::isInitialized() const {
    return initialized_;
}

bool BearMundoSecurity::isSecure() const {
    return secure_;
}

} // namespace security
} // namespace bearmundo 