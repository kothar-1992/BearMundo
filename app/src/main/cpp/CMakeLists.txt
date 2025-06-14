cmake_minimum_required(VERSION 3.22.1)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Add library
add_library(bearmod_security SHARED
    security/KeyAuthNative.cpp
    security/KeyAuthJNI.cpp
)

# Include directories
target_include_directories(bearmod_security PRIVATE
    ${ANDROID_NDK}/sources/android/native_app_glue
    ${ANDROID_NDK}/sources/cxx-stl/llvm-libc++/include
    ${ANDROID_NDK}/sources/cxx-stl/llvm-libc++abi/include
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(bearmod_security
    android
    log
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
)

# Set compile options
target_compile_options(bearmod_security PRIVATE
    -Wall
    -Wextra
    -fexceptions
    -frtti
)

# Set properties
set_target_properties(bearmod_security PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
) 