# BearMod Frida Tools

This directory contains Frida scripts and tools for analyzing and debugging the BearMod application.

## Setup

1. **Install Frida on your PC**:
   ```bash
   pip install frida-tools frida
   ```

2. **Set up Frida on your Android device**:
   ```bash
   # Run the setup script
   chmod +x setup_frida.sh
   ./setup_frida.sh
   ```

   Or manually:
   ```bash
   # Push Frida server to device
   adb push frida-server-16.1.1-android-arm64 /data/local/tmp/frida-server

   # Set executable permissions
   adb shell chmod +x /data/local/tmp/frida-server

   # Start Frida server
   adb shell "/data/local/tmp/frida-server &"

   # Forward Frida server port
   adb forward tcp:27042 tcp:27042
   ```

## Available Scripts

### 1. BearMod Analyzer (`bearmod_analyzer.js`)

A comprehensive script for analyzing the BearMod app. It hooks Java methods, traces native function calls, analyzes SDK behavior, monitors memory access, and intercepts network traffic.

**Usage**:
```bash
frida -U -n com.bearmod -l bearmod_analyzer.js --no-pause
```

### 2. SDK Analyzer (`sdk_analyzer.js`)

A specialized script for analyzing the SDK in BearMod. It focuses on tracking SDK initialization, monitoring SDK function calls, analyzing SDK memory usage, and intercepting SDK network communication.

**Usage**:
```bash
frida -U -n com.bearmod -l sdk_analyzer.js --no-pause
```

### 3. Offset Finder (`offset_finder.js`)

A script for finding and validating memory offsets for game objects. This is particularly useful for SDK development and reverse engineering.

**Usage**:
```bash
frida -U -n com.bearmod -l offset_finder.js --no-pause
```

### 4. Signature Verification Bypass (`bypass-signkill.js`)

A powerful script that bypasses signature verification in Android apps. It hooks into the getPackageInfo() method and returns a fake valid signature, allowing modified apps to run without signature verification errors.

**Usage**:
```bash
frida -U -n com.example.app -l bypass-signkill.js --no-pause
```

For educational purposes, this script is also available in separate parts:
- `bypass-signkill_1.js`: Basic hook setup
- `bypass-signkill_2.js`: Signature extraction
- `bypass-signkill_3.js`: Signature replacement
- `bypass-signkill_4.js`: Additional verification bypasses

See `README_SIGNKILL.md` for detailed information.

## Common Frida Commands

### List Running Processes
```bash
frida-ps -U
```

### Attach to an App
```bash
frida -U -n com.bearmod
```

### Attach to an App & Inject a Script
```bash
frida -U -n com.bearmod -l script.js --no-pause
```

### Spawn an App & Inject a Script
```bash
frida -U -f com.bearmod -l script.js --no-pause
```

## Customizing Scripts

You can customize the scripts by modifying the `config` object at the top of each script. For example:

```javascript
const config = {
    debug: true,
    traceNativeCalls: true,
    monitorJavaClasses: true,
    interceptNetwork: true,
    monitorFileAccess: true,
    logLevel: 'info'
};
```

## Troubleshooting

### Frida Server Not Starting
If the Frida server fails to start, try:
```bash
adb shell "ps | grep frida-server"
adb shell "killall frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### Connection Issues
If you can't connect to the Frida server, check:
```bash
adb forward tcp:27042 tcp:27042
frida-ps -U
```

### Permission Issues
If you encounter permission issues:
```bash
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

## Advanced Usage

### Hooking Specific Functions

To hook a specific function, add code like this to your script:

```javascript
Java.perform(function() {
    var MainActivity = Java.use("com.bearmod.MainActivity");
    MainActivity.onCreate.implementation = function(savedInstanceState) {
        console.log("[*] MainActivity.onCreate() called");
        this.onCreate(savedInstanceState);
        console.log("[*] MainActivity.onCreate() completed");
    };
});
```

### Hooking Native Functions

To hook a native function, add code like this:

```javascript
Interceptor.attach(Module.findExportByName("libbearmod.so", "Java_com_bearmod_NativeUtils_initialize"), {
    onEnter: function(args) {
        console.log("[*] Native initialize function called");
    },
    onLeave: function(retval) {
        console.log("[*] Native initialize function returned: " + retval);
    }
});
```

### Memory Scanning

To scan memory for specific patterns:

```javascript
Memory.scan(moduleBase, moduleSize, "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B D9", {
    onMatch: function(address, size) {
        console.log("[*] Pattern found at: " + address);
    },
    onComplete: function() {
        console.log("[*] Scan completed");
    }
});
```
