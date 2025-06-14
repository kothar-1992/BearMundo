#include "Functions.h"
#include <dlfcn.h>

namespace Helper {
    // Convert jstring to std::string
    std::string jstring2string(JNIEnv *env, jstring jStr) {
        if (!jStr) return "";
        
        const char *cstr = env->GetStringUTFChars(jStr, nullptr);
        std::string str(cstr);
        env->ReleaseStringUTFChars(jStr, cstr);
        
        return str;
    }
    
    // Convert std::string to jstring
    jstring string2jstring(JNIEnv *env, const std::string &str) {
        return env->NewStringUTF(str.c_str());
    }
    
    // Get library base address
    void *getLibraryAddress(const char *libraryName) {
        return dlopen(libraryName, RTLD_LAZY);
    }
    
    // Find pattern in memory
    void *findPattern(void *start, size_t length, const char *pattern, const char *mask) {
        size_t patternLength = strlen(mask);
        
        for (size_t i = 0; i < length - patternLength; i++) {
            bool found = true;
            
            for (size_t j = 0; j < patternLength; j++) {
                if (mask[j] != '?' && pattern[j] != ((char *)start)[i + j]) {
                    found = false;
                    break;
                }
            }
            
            if (found) {
                return (void *)((uintptr_t)start + i);
            }
        }
        
        return nullptr;
    }
    
    // Log debug message
    void logDebug(const char *format, ...) {
        va_list args;
        va_start(args, format);
        __android_log_vprint(ANDROID_LOG_DEBUG, LOG_TAG, format, args);
        va_end(args);
    }
    
    // Log error message
    void logError(const char *format, ...) {
        va_list args;
        va_start(args, format);
        __android_log_vprint(ANDROID_LOG_ERROR, LOG_TAG, format, args);
        va_end(args);
    }
}
