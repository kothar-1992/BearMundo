#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "pch.h"

namespace Helper {
    // String utility functions
    std::string jstring2string(JNIEnv *env, jstring jStr);
    jstring string2jstring(JNIEnv *env, const std::string &str);
    
    // Memory utility functions
    void *getLibraryAddress(const char *libraryName);
    void *findPattern(void *start, size_t length, const char *pattern, const char *mask);
    
    // Logging utility functions
    void logDebug(const char *format, ...);
    void logError(const char *format, ...);
}

#endif // FUNCTIONS_H
