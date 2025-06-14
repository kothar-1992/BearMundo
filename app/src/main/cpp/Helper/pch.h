#ifndef PCH_H
#define PCH_H

// Include NDK compatibility fixes first
#include "NDKCompatibility.h"
#include "BuildFixes.h"

// Standard C++ headers
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <functional>
#include <stdexcept>

// Android specific headers
#include <android/log.h>
#include <jni.h>

// Define logging macros
#define LOG_TAG "bearmod"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#endif // PCH_H
