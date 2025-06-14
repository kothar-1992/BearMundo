# Getting Started with Bear-Mod

This guide will help you get started with the Bear-Mod project.

## Prerequisites

Before you begin, make sure you have the following installed:

- Android Studio Hedgehog (2023.1.1) or newer
- Android SDK Platform 35
- Android NDK 25.1.8937393
- CMake 3.22.1
- Java 17
- Python 3.8+ (for Frida scripts)
- Frida (for dynamic instrumentation)

## Installation

### Option 1: Download Pre-built APK

1. Download the latest APK from the [Releases](https://github.com/BearOwner/BearProject2023/releases) page
2. Enable "Install from Unknown Sources" in your Android settings
3. Install the APK on your device

### Option 2: Build from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/BearOwner/BearProject2023.git
   cd BearProject2023
   ```

2. Set up the environment:
   ```bash
   # Create local.properties with SDK path
   echo "sdk.dir=/path/to/your/android/sdk" > local.properties
   echo "ndk.version=25.1.8937393" >> local.properties
   ```

3. Build the project:
   ```bash
   ./gradlew assembleDebug
   ```

4. Install on your device:
   ```bash
   adb install app/build/outputs/apk/debug/app-debug.apk
   ```

## Basic Usage

### 1. Launch the App

Open the Bear-Mod app on your device. You'll see the main screen with a list of installed applications.

### 2. Select a Target App

Tap on an app from the list to select it as the target for instrumentation.

### 3. Choose Instrumentation Options

After selecting a target app, you'll see a list of available instrumentation options:

- **Root Detection Bypass**: Bypass root detection mechanisms
- **SSL Pinning Bypass**: Bypass SSL certificate pinning
- **Memory Scanner**: Scan and modify memory
- **Network Monitor**: Monitor network traffic
- **File Monitor**: Monitor file access

### 4. Apply Instrumentation

Tap on the "Apply" button to apply the selected instrumentation options to the target app.

### 5. Launch Target App

Tap on the "Launch" button to launch the target app with the applied instrumentation.

## Using Frida Scripts

Bear-Mod includes several Frida scripts for dynamic instrumentation. You can use these scripts directly from your PC.

### 1. Set up Frida on Your Device

```bash
# Push Frida server to device
adb push frida-tools/server/frida-server-16.1.1-android-arm64 /data/local/tmp/frida-server

# Set executable permissions
adb shell chmod +x /data/local/tmp/frida-server

# Start Frida server
adb shell "/data/local/tmp/frida-server &"
```

### 2. Run a Frida Script

```bash
# Using the Frida launcher
python frida-tools/tools/frida_launcher.py run -p com.example.app -s bypass-root.js

# Or directly with Frida
frida -U -n com.example.app -l frida-tools/scripts/bypass-root.js --no-pause
```

## Next Steps

- Learn about the [API](../api/README.md)
- Explore [advanced usage](advanced-usage.md)
- Create your own [Frida scripts](custom-scripts.md)

## Troubleshooting

### Common Issues

1. **App crashes on startup**:
   - Check if the target app has anti-tampering protections
   - Try using a different instrumentation method

2. **Frida server not starting**:
   - Check if your device is rooted
   - Check if you have the correct Frida server version for your device architecture

3. **Instrumentation not working**:
   - Check if the target app is using obfuscation
   - Try using a more specific Frida script

### Getting Help

If you encounter issues not covered here, please:
1. Check the [issue tracker](https://github.com/BearOwner/BearProject2023/issues) on GitHub
2. Create a new issue with detailed information about the problem
3. Include logs, build output, and steps to reproduce the issue
