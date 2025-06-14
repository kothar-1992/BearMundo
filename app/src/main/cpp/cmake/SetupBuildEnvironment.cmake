# SetupBuildEnvironment.cmake
# This module sets up the build environment with proper flags and definitions

# Detect build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
    message(STATUS "Build type not specified, defaulting to Release")
endif()

# Set appropriate flags for each build type
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -D_DEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

# Add platform-specific definitions
if(ANDROID)
    add_definitions(-DPLATFORM_ANDROID=1)
    
    # Set ABI-specific flags
    if(ANDROID_ABI STREQUAL "arm64-v8a")
        add_definitions(-DPLATFORM_ARM64=1)
    elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
        add_definitions(-DPLATFORM_ARM32=1)
    elseif(ANDROID_ABI STREQUAL "x86_64")
        add_definitions(-DPLATFORM_X64=1)
    elseif(ANDROID_ABI STREQUAL "x86")
        add_definitions(-DPLATFORM_X86=1)
    endif()
endif()

# Add debug definitions
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DENABLE_LOGGING=1)
    add_definitions(-DENABLE_ASSERTIONS=1)
else()
    add_definitions(-DENABLE_LOGGING=0)
    add_definitions(-DENABLE_ASSERTIONS=0)
endif()

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add timestamp to build
string(TIMESTAMP BUILD_TIMESTAMP "%Y-%m-%d %H:%M:%S")
add_definitions(-DBUILD_TIMESTAMP="${BUILD_TIMESTAMP}")

# Generate compile_commands.json for tools like clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Print build configuration summary
message(STATUS "Build configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Android ABI: ${ANDROID_ABI}")
message(STATUS "  Android platform: ${ANDROID_PLATFORM}")
message(STATUS "  Android STL: ${ANDROID_STL}")
message(STATUS "  Build timestamp: ${BUILD_TIMESTAMP}")
