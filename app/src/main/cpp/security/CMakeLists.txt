# ===========================
# Bear Mundo Security CMakeLists.txt
# ===========================

cmake_minimum_required(VERSION 3.22.1)
project(BearMundoSecurity)

# Android NDK setup
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set build type (Release for maximum optimization)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# JNI and Android log
find_package(JNI REQUIRED)
find_library(log-lib log)
find_library(android-lib android)

# === Source Files ===
file(GLOB BEARMUNDO_SRC
    "BearMundoSecurity.cpp"
    "StealthOperations.cpp"
    "AntiDetection.cpp"
    "ContainerManager.cpp"
    "Main.cpp"
    "KeyAuth.cpp"
    "*.h"
)

# === Library Build ===
add_library(bearmundosecurity SHARED ${BEARMUNDO_SRC})

# === Include Paths ===
target_include_directories(bearmundosecurity PRIVATE
    ${JNI_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../core
    ${CMAKE_CURRENT_SOURCE_DIR}/../Helper
)

# === Link Libraries ===
target_link_libraries(bearmundosecurity
    ${log-lib}
    ${android-lib}
)

# === Optimization and Anti-Reverse Flags ===
target_compile_options(bearmundosecurity PRIVATE
    -Wall
    -O3                    # Full optimization
    -fvisibility=hidden    # Hide symbols by default
    -fstack-protector-strong
    -fPIC
    -fdata-sections -ffunction-sections
    -Wno-unused-variable
    -Wno-unused-parameter
)

set_target_properties(bearmundosecurity PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    OUTPUT_NAME "bear_mundo_security"
)

# === ABI Filters (Only arm64-v8a, add armeabi-v7a if needed) ===
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_ANDROID_RTTI OFF) # Extra hardening (optional)

# === Post-build Obfuscation (Optional, advanced users) ===
# add_custom_command(TARGET bearmundosecurity POST_BUILD
#    COMMAND "strip" --strip-unneeded $<TARGET_FILE:bearmundosecurity>
# )

# === Install Rule (for .aar inclusion) ===
install(TARGETS bearmundosecurity
    LIBRARY DESTINATION lib/${CMAKE_ANDROID_ARCH_ABI}
)

# ===========================
# End Bear Mundo Security CMakeLists.txt
# =========================== 