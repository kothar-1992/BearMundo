# FindSDKDependencies.cmake
# This module checks for required SDK dependencies and sets up paths

# Check if SDK directory exists
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/SDK")
    message(WARNING "SDK directory not found. Some features may be disabled.")
    set(SDK_AVAILABLE FALSE)
else()
    set(SDK_AVAILABLE TRUE)
    message(STATUS "SDK directory found at ${CMAKE_CURRENT_SOURCE_DIR}/SDK")
    
    # Check for critical SDK files
    set(CRITICAL_SDK_FILES
        "SDK/PUBGM_Basic.hpp"
        "SDK/PUBGM_CoreUObject_classes.hpp"
        "SDK/PUBGM_Engine_classes.hpp"
    )
    
    foreach(SDK_FILE ${CRITICAL_SDK_FILES})
        if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SDK_FILE}")
            message(WARNING "Critical SDK file missing: ${SDK_FILE}")
            set(SDK_AVAILABLE FALSE)
        endif()
    endforeach()
endif()

# Set SDK compilation options based on availability
if(SDK_AVAILABLE)
    message(STATUS "SDK is available - enabling SDK features")
    add_definitions(-DSDK_AVAILABLE=1)
    
    # Create a list of SDK source files to compile
    file(GLOB_RECURSE SDK_SOURCES 
        "${CMAKE_CURRENT_SOURCE_DIR}/SDK/*.cpp"
    )
    
    # Exclude problematic files
    list(FILTER SDK_SOURCES EXCLUDE REGEX ".*PUBGM_ShadowTrackerExtra_functions\\.cpp$")
    list(FILTER SDK_SOURCES EXCLUDE REGEX ".*PUBGM_Client_functions\\.cpp$")
    
    # Count SDK files
    list(LENGTH SDK_SOURCES SDK_SOURCE_COUNT)
    message(STATUS "Found ${SDK_SOURCE_COUNT} SDK source files to compile")
    
    # Create SDK library
    if(SDK_SOURCE_COUNT GREATER 0)
        add_library(sdk_lib STATIC ${SDK_SOURCES})
        target_include_directories(sdk_lib PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/SDK
        )
        set(SDK_LIB sdk_lib)
    else()
        set(SDK_LIB "")
    endif()
else()
    message(STATUS "SDK is not available - disabling SDK features")
    add_definitions(-DSDK_AVAILABLE=0)
    set(SDK_LIB "")
endif()

# Export variables
set(SDK_AVAILABLE ${SDK_AVAILABLE} PARENT_SCOPE)
set(SDK_LIB ${SDK_LIB} PARENT_SCOPE)
