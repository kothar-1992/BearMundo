# Bear-Mod Project Map

This document outlines the complete structure of the Bear-Mod Project, including all components, dependencies, and integration paths.

## Project Overview

Bear-Mod is an Android application with native C++ components designed for dynamic instrumentation and security analysis. It provides a framework for analyzing and modifying Android applications at runtime.

## Disclaimer

Bear-Mod is designed for security researchers, app developers, and educational purposes only.
Users must:
1. Only analyze applications they own or have explicit permission to test
2. Respect intellectual property rights and terms of service
3. Use findings responsibly through proper disclosure channels
4. Not use this tool to access unauthorized content or services

Misuse of this tool may violate laws including but not limited to the Computer Fraud and Abuse Act, Digital Millennium Copyright Act, and equivalent legislation in other jurisdictions.

## Directory Structure

```
BearProject2023/
├── .github/                        # GitHub configuration
│   └── workflows/                  # CI/CD workflows
│       ├── build.yml               # Main build workflow
│       ├── release.yml             # Release workflow
│       └── test.yml                # Testing workflow
├── app/                            # Android application
│   ├── src/
│   │   ├── main/
│   │   │   ├── cpp/                # Native C++ code
│   │   │   │   ├── core/           # Core native functionality
│   │   │   │   │   ├── hooks/      # Hooking mechanisms
│   │   │   │   │   ├── memory/     # Memory manipulation
│   │   │   │   │   └── utils/      # Utility functions
│   │   │   │   ├── external/       # External integrations
│   │   │   │   │   ├── frida/      # Frida integration
│   │   │   │   │   └── dobby/      # Dobby hooking library
│   │   │   │   ├── sdk/            # SDK-related code (optional)
│   │   │   │   ├── CMakeLists.txt  # Main CMake configuration
│   │   │   │   └── native-lib.cpp  # JNI entry points
│   │   │   ├── java/               # Java code
│   │   │   │   └── com/bearmod/
│   │   │   │       ├── core/       # Core Java functionality
│   │   │   │       │   ├── hooks/  # Java hooking mechanisms
│   │   │   │       │   └── utils/  # Utility classes
│   │   │   │       ├── external/   # External Java integrations
│   │   │   │       ├── ui/         # User interface
│   │   │   │       └── MainActivity.java
│   │   │   └── res/                # Android resources
│   │   └── test/                   # Unit tests
│   └── build.gradle                # App build configuration
├── frida-tools/                    # Frida scripts and tools
│   ├── scripts/                    # Frida scripts
│   │   ├── bypass-root.js          # Root detection bypass
│   │   ├── bypass-ssl.js           # SSL pinning bypass
│   │   └── analyzer.js             # App analysis script
│   ├── server/                     # Frida server binaries
│   └── tools/                      # Helper tools
├── docs/                           # Documentation
│   ├── api/                        # API documentation
│   ├── guides/                     # User guides
│   └── development/                # Development documentation
├── scripts/                        # Build and utility scripts
│   ├── setup.sh                    # Environment setup script
│   └── release.sh                  # Release preparation script
├── build.gradle                    # Project build configuration
├── gradle.properties               # Gradle properties
├── settings.gradle                 # Gradle settings
├── local.properties                # Local build properties (git-ignored)
├── README.md                       # Project README
└── LICENSE                         # Project license
```

## Dependency Map

### Core Dependencies

- **Android SDK**: API level 29+ (Android 10.0+)
- **Android NDK**: Version 25.1.8937393
- **CMake**: Version 3.22.1
- **JDK**: Version 17
- **Gradle**: Version 8.0+
- **C++ Standard**: C++17

### External Dependencies

- **Frida**: Dynamic instrumentation toolkit
- **Dobby**: Lightweight hooking framework
- **KittyMemory**: Memory manipulation library
- **Substrate**: Hooking library for older Android versions

### Optional Dependencies

- **SDK Files**: Game-specific SDK files (if available)
- **OpenSSL**: For cryptographic operations
- **curl**: For network operations

## Integration Points

### 1. Native-Java Bridge

```
app/src/main/cpp/native-lib.cpp ↔ app/src/main/java/com/bearmod/core/NativeBridge.java
```

### 2. Frida Integration

```
app/src/main/cpp/external/frida/frida_integration.cpp ↔ frida-tools/scripts/*.js
```

### 3. UI-Core Integration

```
app/src/main/java/com/bearmod/ui/* ↔ app/src/main/java/com/bearmod/core/*
```

### 4. SDK Integration (Optional)

```
app/src/main/cpp/sdk/* ↔ app/src/main/cpp/core/hooks/*
```

## Build Paths

### 1. Full Build (with SDK)

```
CMake → Native Libraries → Java Compilation → APK Packaging → Signing
```

### 2. Minimal Build (without SDK)

```
CMake (SDK_AVAILABLE=0) → Native Libraries → Java Compilation → APK Packaging → Signing
```

### 3. Debug Build

```
CMake (CMAKE_BUILD_TYPE=Debug) → Native Libraries → Java Compilation → Debug APK
```

## Deployment Paths

### 1. GitHub Release

```
Build → Test → Create GitHub Release → Upload APK
```

### 2. Direct Installation

```
Build → ADB Install
```

### 3. CI/CD Pipeline

```
GitHub Push → GitHub Actions → Build → Test → Release
```

## Extension Points

The project is designed to be extended in the following ways:

1. **New Frida Scripts**: Add new scripts to `frida-tools/scripts/`
2. **New Hooking Mechanisms**: Extend `app/src/main/cpp/core/hooks/`
3. **New UI Features**: Add new activities/fragments to `app/src/main/java/com/bearmod/ui/`
4. **New Analysis Tools**: Add new tools to `app/src/main/java/com/bearmod/core/analysis/`

## Version Control Strategy

- **main**: Stable releases
- **develop**: Development branch
- **feature/***: Feature branches
- **release/***: Release preparation branches
- **hotfix/***: Hotfix branches

## Backup and Recovery Paths

1. **Local Backups**: `scripts/backup.sh`
2. **GitHub Releases**: Tagged releases on GitHub
3. **Artifact Storage**: Build artifacts stored in GitHub Actions
