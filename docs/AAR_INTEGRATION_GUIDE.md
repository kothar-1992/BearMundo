# BearMod AAR Library Integration Guide

## Overview

The BearMod AAR library provides advanced Android security analysis and hooking capabilities. This guide covers integration, functionality, and compatibility considerations.

## 🏗️ AAR Build Configuration

### Build System
- **Build Tool**: Gradle with Kotlin DSL (build.gradle.kts)
- **Android Gradle Plugin**: 8.10.1
- **Kotlin Version**: 1.9.22
- **Target SDK**: 34
- **Min SDK**: 24

### Native Components
- **NDK**: C++17 with STL shared library
- **Architectures**: arm64-v8a, armeabi-v7a, x86, x86_64
- **Native Library**: libbearmod.so

## 📦 AAR Contents

### Java/Kotlin Classes
```
com.bearmod.core.BearModCore          - Main entry point
com.bearmod.core.NativeBridge         - JNI interface
com.bearmod.core.hooks.HookManager    - Hook management
com.bearmod.targetapp.SignatureVerifier - Signature validation
com.bearmod.NativeUtils               - Utility functions
```

### Native Libraries
```
lib/arm64-v8a/libbearmod.so
lib/armeabi-v7a/libbearmod.so
lib/x86/libbearmod.so
lib/x86_64/libbearmod.so
```

### Frida Scripts (Assets)
```
assets/frida-scripts/bearmod_analyzer.js
assets/frida-scripts/anti-detection.js
assets/frida-scripts/bypass-root.js
assets/frida-scripts/bypass-ssl.js
assets/frida-scripts/bypass-signkill.js
```

## 🔧 Integration Steps

### 1. Add AAR Dependency

#### Option A: Local AAR
```kotlin
// app/build.gradle.kts
dependencies {
    implementation(files("libs/bearmod-library-1.0.0.aar"))
}
```

#### Option B: Maven Repository
```kotlin
// app/build.gradle.kts
dependencies {
    implementation("com.bearmod:bearmod-library:1.0.0")
}
```

### 2. Update AndroidManifest.xml

```xml
<!-- Host app manifest -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    
    <!-- Required permissions (automatically merged from AAR) -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    
    <application
        android:name=".MyApplication"
        android:allowBackup="true"
        android:theme="@style/AppTheme">
        
        <!-- Your activities -->
        
    </application>
</manifest>
```

### 3. Initialize in Application Class

```kotlin
// MyApplication.kt
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Initialize BearMod
        val bearMod = BearModCore.getInstance(this)
        val success = bearMod.initialize()
        
        if (success) {
            Log.i("MyApp", "BearMod initialized successfully")
        } else {
            Log.e("MyApp", "Failed to initialize BearMod")
        }
    }
}
```

## 🎯 Core Functionality Analysis

### ✅ WILL WORK in AAR Format

#### 1. **Native Library Loading**
- ✅ **Status**: Fully functional
- **Details**: libbearmod.so loads correctly from AAR
- **Usage**: Automatic loading via System.loadLibrary()

#### 2. **JNI Bridge**
- ✅ **Status**: Fully functional  
- **Details**: Native-Java communication works seamlessly
- **Usage**: NativeBridge class provides interface

#### 3. **Signature Verification**
- ✅ **Status**: Fully functional
- **Details**: Can verify host app signatures
- **Usage**: SignatureVerifier.verifySignature(context)

#### 4. **Core Hooking Infrastructure**
- ✅ **Status**: Fully functional
- **Details**: HookManager and native hooks work
- **Usage**: Access via BearModCore.getHookManager()

#### 5. **Basic Frida Script Loading**
- ✅ **Status**: Functional with modifications
- **Details**: Scripts accessible via assets
- **Usage**: Load from assets/frida-scripts/

### ⚠️ REQUIRES MODIFICATIONS

#### 1. **Frida Integration**
- ⚠️ **Status**: Requires host app setup
- **Issues**: 
  - Frida server must be running on device
  - Host app needs Frida gadget or external injection
  - Scripts need to target host app process
- **Solution**: 
  ```kotlin
  // Host app needs to load Frida scripts
  val scriptContent = assets.open("frida-scripts/bearmod_analyzer.js")
      .bufferedReader().use { it.readText() }
  ```

#### 2. **Process Hooking**
- ⚠️ **Status**: Limited scope
- **Issues**: Can only hook within host app process
- **Solution**: Focus on host app analysis rather than system-wide

### ❌ WON'T WORK in AAR Format

#### 1. **Standalone MainActivity**
- ❌ **Status**: Not applicable
- **Reason**: AAR libraries don't have launcher activities
- **Alternative**: Host app provides UI

#### 2. **Independent Process Analysis**
- ❌ **Status**: Not possible
- **Reason**: AAR runs within host app process
- **Alternative**: Analyze host app instead

#### 3. **System-wide Frida Injection**
- ❌ **Status**: Not possible
- **Reason**: Requires root and external Frida setup
- **Alternative**: Use Frida gadget in host app

## 🔒 Security Considerations

### Host App Requirements
1. **Root Access**: Not required for basic functionality
2. **Frida Setup**: Required for advanced hooking
3. **Permissions**: Inherited from AAR manifest

### Signature Validation
```kotlin
// Verify host app signature
val isValid = SignatureVerifier.verifySignature(context, "expected_signature")
if (!isValid) {
    // Handle unauthorized usage
}
```

## 🧪 Testing Integration

### Unit Tests
```kotlin
@Test
fun testBearModInitialization() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val bearMod = BearModCore.getInstance(context)
    assertTrue(bearMod.initialize())
}
```

### Integration Tests
```kotlin
@Test
fun testNativeLibraryLoading() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val bearMod = BearModCore.getInstance(context)
    bearMod.initialize()
    
    // Test native bridge
    assertTrue(NativeBridge.isInitialized())
}
```

## 📋 Compatibility Matrix

| Feature | Standalone App | AAR Library | Notes |
|---------|---------------|-------------|-------|
| Native Libraries | ✅ | ✅ | Full compatibility |
| JNI Bridge | ✅ | ✅ | Full compatibility |
| Signature Verification | ✅ | ✅ | Works on host app |
| Basic Hooking | ✅ | ✅ | Within process only |
| Frida Scripts | ✅ | ⚠️ | Requires host setup |
| UI Components | ✅ | ❌ | Host app provides UI |
| Process Injection | ✅ | ❌ | AAR scope limited |

## 🚀 Advanced Usage

### Custom Hook Implementation
```kotlin
// In host app
val bearMod = BearModCore.getInstance(this)
val hookManager = bearMod.hookManager

// Hook host app methods
hookManager.hookMethod("com.myapp.MainActivity", "onCreate") { args ->
    Log.i("BearMod", "MainActivity.onCreate hooked!")
    // Call original method
}
```

### Frida Script Integration
```kotlin
// Load and execute Frida script
val scriptAssets = assets.list("frida-scripts")
scriptAssets?.forEach { scriptName ->
    val script = assets.open("frida-scripts/$scriptName")
        .bufferedReader().use { it.readText() }
    
    // Execute with Frida (requires Frida setup)
    fridaSession.createScript(script).load()
}
```

## 🔧 Build Commands

```bash
# Build AAR
./gradlew assembleRelease

# Optimize AAR
./gradlew optimizeAar

# Validate AAR
./gradlew validateAar

# Publish to local repository
./gradlew publishToMavenLocal
```

## 📝 Conclusion

The BearMod AAR library successfully packages core functionality while maintaining compatibility with host applications. Key limitations involve Frida integration and process scope, but core security analysis and hooking capabilities remain fully functional.
