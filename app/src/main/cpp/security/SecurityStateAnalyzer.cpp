#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>
#include <sys/ptrace.h>
#include <sys/syscall.h>
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

#define LOG_TAG "SecurityStateAnalyzer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

using namespace std;

class SecurityStateAnalyzer {
private:
    static SecurityStateAnalyzer* instance;
    static mutex instanceMutex;
    bool isAnalyzing;
    thread analyzerThread;
    mutex stateMutex;
    map<string, bool> securityState;
    vector<string> suspiciousPatterns;
    vector<string> protectedRegions;
    int seccompFilter;

    SecurityStateAnalyzer() : isAnalyzing(false), seccompFilter(-1) {
        initializePatterns();
        setupSeccompFilter();
    }

    void initializePatterns() {
        // Memory access patterns
        suspiciousPatterns.push_back("ptrace");
        suspiciousPatterns.push_back("inject");
        suspiciousPatterns.push_back("hook");
        suspiciousPatterns.push_back("debug");
        suspiciousPatterns.push_back("trace");
        suspiciousPatterns.push_back("frida");
        suspiciousPatterns.push_back("xposed");
        suspiciousPatterns.push_back("substrate");
    }

    void setupSeccompFilter() {
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

        seccompFilter = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
        if (seccompFilter < 0) {
            LOGE("Failed to set up seccomp filter");
        }
    }

    void analyzeMemoryRegions() {
        ifstream maps("/proc/self/maps");
        string line;
        regex protectedRegex("(frida|xposed|substrate|magisk)");

        while (getline(maps, line)) {
            if (regex_search(line, protectedRegex)) {
                stringstream ss(line);
                string start, end;
                ss >> start >> end;
                
                // Convert hex addresses to long
                long startAddr = stol(start, nullptr, 16);
                long endAddr = stol(end, nullptr, 16);
                
                // Mark region as protected
                protectedRegions.push_back(start + "-" + end);
                
                // Set memory protection
                mprotect((void*)startAddr, endAddr - startAddr, 
                        PROT_READ | PROT_WRITE | PROT_EXEC);
            }
        }
    }

    void checkForHooks() {
        Dl_info info;
        void* handle = dlopen("libc.so", RTLD_NOW);
        if (handle) {
            void* symbol = dlsym(handle, "ptrace");
            if (symbol && dladdr(symbol, &info)) {
                // Check if symbol is in expected location
                if (info.dli_fbase != handle) {
                    securityState["hook_detected"] = true;
                }
            }
            dlclose(handle);
        }
    }

    void checkForDebuggers() {
        int status;
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            securityState["debugger_detected"] = true;
        } else {
            ptrace(PTRACE_TRACEME, 0, 0, 0);
        }
    }

    void checkForEmulators() {
        char prop[PROP_VALUE_MAX];
        if (__system_property_get("ro.kernel.qemu", prop) > 0) {
            securityState["emulator_detected"] = true;
        }
    }

    void checkForRoot() {
        const char* paths[] = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        };

        for (const char* path : paths) {
            if (access(path, F_OK) == 0) {
                securityState["root_detected"] = true;
                break;
            }
        }
    }

    void analyzeSecurityState() {
        while (isAnalyzing) {
            lock_guard<mutex> lock(stateMutex);
            
            // Reset state
            securityState.clear();
            
            // Run security checks
            checkForHooks();
            checkForDebuggers();
            checkForEmulators();
            checkForRoot();
            analyzeMemoryRegions();
            
            // Sleep to prevent high CPU usage
            this_thread::sleep_for(chrono::milliseconds(100));
        }
    }

public:
    static SecurityStateAnalyzer* getInstance() {
        lock_guard<mutex> lock(instanceMutex);
        if (!instance) {
            instance = new SecurityStateAnalyzer();
        }
        return instance;
    }

    void startAnalysis() {
        if (isAnalyzing) return;
        
        isAnalyzing = true;
        analyzerThread = thread(&SecurityStateAnalyzer::analyzeSecurityState, this);
        LOGI("Security state analysis started");
    }

    void stopAnalysis() {
        if (!isAnalyzing) return;
        
        isAnalyzing = false;
        if (analyzerThread.joinable()) {
            analyzerThread.join();
        }
        LOGI("Security state analysis stopped");
    }

    Json::Value getSecurityState() {
        lock_guard<mutex> lock(stateMutex);
        Json::Value state;
        
        for (const auto& pair : securityState) {
            state[pair.first] = pair.second;
        }
        
        return state;
    }

    ~SecurityStateAnalyzer() {
        stopAnalysis();
        if (seccompFilter >= 0) {
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED);
        }
    }
};

SecurityStateAnalyzer* SecurityStateAnalyzer::instance = nullptr;
mutex SecurityStateAnalyzer::instanceMutex;

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_bearmod_security_ai_SecurityAnalyzer_nativeGetSecurityState(JNIEnv* env, jclass clazz) {
    auto analyzer = SecurityStateAnalyzer::getInstance();
    Json::Value state = analyzer->getSecurityState();
    
    Json::FastWriter writer;
    string jsonStr = writer.write(state);
    
    return env->NewStringUTF(jsonStr.c_str());
}

JNIEXPORT void JNICALL
Java_com_bearmod_security_ai_SecurityAnalyzer_nativeStartAnalysis(JNIEnv* env, jclass clazz) {
    SecurityStateAnalyzer::getInstance()->startAnalysis();
}

JNIEXPORT void JNICALL
Java_com_bearmod_security_ai_SecurityAnalyzer_nativeStopAnalysis(JNIEnv* env, jclass clazz) {
    SecurityStateAnalyzer::getInstance()->stopAnalysis();
}

} // extern "C" 