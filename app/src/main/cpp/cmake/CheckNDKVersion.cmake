# CheckNDKVersion.cmake
# This module checks the NDK version and sets up appropriate flags

# Try to detect NDK version
if(DEFINED ANDROID_NDK)
    # Extract version from source.properties file
    if(EXISTS "${ANDROID_NDK}/source.properties")
        file(READ "${ANDROID_NDK}/source.properties" NDK_PROPS_CONTENT)
        string(REGEX MATCH "Pkg\\.Revision = ([0-9]+)\\.([0-9]+)\\.([0-9]+)" NDK_VERSION_MATCH "${NDK_PROPS_CONTENT}")
        
        if(NDK_VERSION_MATCH)
            set(NDK_MAJOR_VERSION ${CMAKE_MATCH_1})
            set(NDK_MINOR_VERSION ${CMAKE_MATCH_2})
            set(NDK_PATCH_VERSION ${CMAKE_MATCH_3})
            set(NDK_VERSION "${NDK_MAJOR_VERSION}.${NDK_MINOR_VERSION}.${NDK_PATCH_VERSION}")
            message(STATUS "Detected NDK version: ${NDK_VERSION}")
            
            # Set appropriate flags based on NDK version
            if(NDK_MAJOR_VERSION GREATER_EQUAL 25)
                # NDK r25+ settings
                message(STATUS "Using NDK r25+ settings")
                add_definitions(-DNDK_VERSION_MAJOR=${NDK_MAJOR_VERSION})
                add_definitions(-DNDK_R25_OR_LATER=1)
                
                # NDK r25+ uses a different path for clang
                set(CLANG_INCLUDE_PATH "${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/lib64/clang/${NDK_MAJOR_VERSION}.0.${NDK_MINOR_VERSION}/include")
            elseif(NDK_MAJOR_VERSION GREATER_EQUAL 23)
                # NDK r23-r24 settings
                message(STATUS "Using NDK r23-r24 settings")
                add_definitions(-DNDK_VERSION_MAJOR=${NDK_MAJOR_VERSION})
                add_definitions(-DNDK_R23_OR_LATER=1)
                
                # NDK r23-r24 uses a different path for clang
                set(CLANG_INCLUDE_PATH "${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/lib64/clang/${NDK_MAJOR_VERSION}.0.${NDK_MINOR_VERSION}/include")
            elseif(NDK_MAJOR_VERSION GREATER_EQUAL 21)
                # NDK r21-r22 settings
                message(STATUS "Using NDK r21-r22 settings")
                add_definitions(-DNDK_VERSION_MAJOR=${NDK_MAJOR_VERSION})
                add_definitions(-DNDK_R21_OR_LATER=1)
                
                # NDK r21-r22 uses a different path for clang
                set(CLANG_INCLUDE_PATH "${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/lib64/clang/${NDK_MAJOR_VERSION}.0.${NDK_MINOR_VERSION}/include")
            else()
                # Older NDK settings
                message(STATUS "Using older NDK settings")
                add_definitions(-DNDK_VERSION_MAJOR=${NDK_MAJOR_VERSION})
                
                # Older NDK versions use a different path for clang
                set(CLANG_INCLUDE_PATH "${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/lib64/clang/${NDK_MAJOR_VERSION}.0/include")
            endif()
        else()
            message(WARNING "Could not parse NDK version from source.properties")
            set(CLANG_INCLUDE_PATH "${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/lib64/clang/14.0.6/include")
        endif()
    else()
        message(WARNING "NDK source.properties file not found")
        set(CLANG_INCLUDE_PATH "${ANDROID_NDK}/toolchains/llvm/prebuilt/${ANDROID_HOST_TAG}/lib64/clang/14.0.6/include")
    endif()
else()
    message(WARNING "ANDROID_NDK not defined")
    set(CLANG_INCLUDE_PATH "")
endif()

# Export variables
set(CLANG_INCLUDE_PATH ${CLANG_INCLUDE_PATH} PARENT_SCOPE)
