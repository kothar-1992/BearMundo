# BearProject2023 - Android Security Analysis Framework

[![BearMod CI](https://github.com/ZeusOwner/BearProject2023/actions/workflows/android.yml/badge.svg)](https://github.com/ZeusOwner/BearProject2023/actions/workflows/android.yml)

## Overview

BearProject2023 is a comprehensive Android application framework designed for dynamic instrumentation and security analysis. It combines native C++ components with Java-based UI and provides extensive Frida integration for runtime analysis.

**⚠️ DISCLAIMER**: This tool is designed for security researchers, app developers, and educational purposes only. Users must only analyze applications they own or have explicit permission to test.

## Key Features

- **Dynamic Instrumentation**: Advanced Frida integration for runtime analysis
- **Native C++ Core**: High-performance native components for memory manipulation
- **Anti-Detection**: Stealth techniques to avoid detection mechanisms
- **Modular Architecture**: Clean separation between core functionality and UI
- **Comprehensive Logging**: Detailed logging and analysis capabilities
- **CI/CD Integration**: Automated building, testing, and deployment

## Quick Start

### Prerequisites

- **Android Studio**: Hedgehog (2023.1.1) or newer
- **Android SDK**: Platform 35 (Android 14)
- **Android NDK**: Version 25.1.8937393
- **CMake**: Version 3.22.1
- **Java**: JDK 17
- **Python**: 3.6+ (for utility scripts)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ZeusOwner/BearProject2023.git
   cd BearProject2023
   ```

2. **Configure local.properties**:
   ```properties
   sdk.dir=C:\\Users\\YourUsername\\AppData\\Local\\Android\\Sdk
   ndk.version=25.1.8937393
   cmake.version=3.22.1
   ```

3. **Setup environment**:
   ```bash
   # Run setup script
   .\scripts\setup\setup-existing-repo.ps1

   # Verify SDK dependencies
   python scripts\utils\check_sdk.py app/src/main/cpp
   ```

4. **Build the project**:
   ```bash
   # Quick build and install
   .\scripts\build\build-and-install.ps1

   # Or build in Android Studio
   # File > Sync Project with Gradle Files
   # Build > Make Project
   ```

## Project Structure

```
BearProject2023/
├── app/                    # Android application
│   ├── src/main/
│   │   ├── cpp/           # Native C++ code
│   │   ├── java/          # Java source code
│   │   └── res/           # Android resources
│   └── build.gradle       # App build configuration
├── frida-tools/           # Frida scripts and tools
│   ├── scripts/           # Analysis and bypass scripts
│   └── tools/             # Helper tools
├── android/               # Android-specific tools
│   └── scripts/           # Additional analysis scripts
├── scripts/               # Build and utility scripts
│   ├── build/             # Build scripts
│   ├── setup/             # Setup scripts
│   └── utils/             # Utility scripts
├── docs/                  # Documentation
│   ├── api/               # API documentation
│   └── guides/            # User guides
└── target-app/            # Target application for testing
```

## Core Components

### Native Layer (`app/src/main/cpp/`)
- **Core**: Memory manipulation and hooking mechanisms
- **JNI Bridge**: Java-Native interface
- **SDK Integration**: Game-specific SDK handling

### Java Layer (`app/src/main/java/com/bearmod/`)
- **Core**: Main application logic and native bridge
- **UI**: User interface components
- **Utils**: Utility classes and helpers

### Frida Integration (`frida-tools/`)
- **Analysis Scripts**: Comprehensive app analysis
- **Bypass Scripts**: Anti-detection and bypass mechanisms
- **Tools**: Helper utilities and launchers

## Usage

### Basic Analysis
```bash
# Run comprehensive analysis
frida -U -n com.bearmod -l frida-tools/scripts/bearmod_analyzer.js --no-pause

# Run SDK-specific analysis
frida -U -n com.bearmod -l frida-tools/sdk_analyzer.js --no-pause

# Enable anti-detection
frida -U -n com.bearmod -l frida-tools/scripts/anti-detection.js --no-pause
```

### Bypass Techniques
```bash
# Bypass signature verification
frida -U -n com.target.app -l frida-tools/scripts/bypass-signkill.js --no-pause

# Bypass root detection
frida -U -n com.target.app -l frida-tools/scripts/bypass-root.js --no-pause

# Bypass SSL pinning
frida -U -n com.target.app -l frida-tools/scripts/bypass-ssl.js --no-pause
```

## Development

### Building from Source
```bash
# Clean build
.\scripts\build\build-app.bat

# Build and install on device
.\scripts\build\build-and-install.ps1

# Build for specific device
.\scripts\build\build-device.bat
```

### Testing
```bash
# Run unit tests
./gradlew test

# Run instrumentation tests
./gradlew connectedAndroidTest

# Check code quality
./gradlew lint
```

## Documentation

- **[Detailed Documentation](docs/DETAILED_README.md)** - Comprehensive project documentation
- **[Project Map](docs/PROJECT_MAP.md)** - Complete project structure and dependencies
- **[Implementation Paths](docs/IMPLEMENTATION_PATHS.md)** - Development and deployment paths
- **[API Documentation](docs/api/README.md)** - API reference and usage
- **[Getting Started Guide](docs/guides/getting-started.md)** - Step-by-step setup guide

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Notice

This tool is intended for legitimate security research and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## License

MIT License - see [LICENSE](LICENSE) file for details.
