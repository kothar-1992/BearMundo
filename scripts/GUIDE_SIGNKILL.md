# How to Use the Signature Verification Bypass (SignKill)

This guide provides step-by-step instructions for using the Signature Verification Bypass script to analyze and modify Android applications.

## Prerequisites

1. A rooted Android device or emulator
2. Frida installed on your PC (`pip install frida-tools frida`)
3. Frida server running on your Android device
4. The target application installed on your device

## Basic Usage

### Step 1: Start Frida Server on Your Device

```bash
# Push Frida server to device (if not already done)
adb push frida-server-16.1.1-android-arm64 /data/local/tmp/frida-server

# Set executable permissions
adb shell chmod +x /data/local/tmp/frida-server

# Start Frida server
adb shell "/data/local/tmp/frida-server &"

# Forward Frida server port
adb forward tcp:27042 tcp:27042
```

### Step 2: Verify Frida Connection

```bash
# List running processes to verify connection
frida-ps -U
```

You should see a list of processes running on your device.

### Step 3: Run the SignKill Script

```bash
# Run the script on your target app
frida -U -n com.example.app -l bypass-signkill.js --no-pause
```

### Step 4: Observe the Output

The script will output information about signature checks being bypassed:

```
[*] Signature Verification Bypass (SignKill) Loaded
[*] Java VM initialized
[+] PackageManager.getPackageArchiveInfo hooked
[+] SignatureVerifier.verifySignature hooked
[*] Signature verification bypass complete
[*] Signature verification bypass script initialized
[+] Spoofing signature check for com.example.app
[+] Signature spoofed for com.example.app
```

## Advanced Usage

### Extracting the Original Signature

To extract the original signature of an app for analysis:

1. Run the script on the target app
2. Look for the "Original Signature Summary" in the output
3. Copy the signature for further analysis

### Modifying an App and Bypassing Signature Verification

1. Decompile the target app using a tool like APKTool
2. Make your modifications to the app
3. Recompile the app
4. Install the modified app on your device
5. Run the SignKill script to bypass signature verification
6. Launch the app - it should now run without signature verification errors

### Using the Script in Parts for Learning

To understand how the bypass works step by step:

1. Start with Part 1 to see the basic hook setup:
   ```bash
   frida -U -n com.example.app -l bypass-signkill_1.js --no-pause
   ```

2. Move to Part 2 to see how signatures are extracted:
   ```bash
   frida -U -n com.example.app -l bypass-signkill_2.js --no-pause
   ```

3. Continue with Part 3 to see how signatures are replaced:
   ```bash
   frida -U -n com.example.app -l bypass-signkill_3.js --no-pause
   ```

4. Finally, use Part 4 to see additional verification bypasses:
   ```bash
   frida -U -n com.example.app -l bypass-signkill_4.js --no-pause
   ```

## Troubleshooting

### Script Not Working

If the script doesn't work as expected:

1. Make sure Frida server is running on your device
2. Verify that you can connect to the device with `frida-ps -U`
3. Check if the app is using additional protection mechanisms
4. Try using the full script instead of individual parts

### App Still Crashing

If the app still crashes after applying the bypass:

1. The app might be using additional integrity checks
2. Try hooking other verification methods specific to the app
3. Look for custom signature verification implementations

## DISCLAIMER

Bear-Mod is designed for security researchers, app developers, and educational purposes only.
Users must:
1. Only analyze applications they own or have explicit permission to test
2. Respect intellectual property rights and terms of service
3. Use findings responsibly through proper disclosure channels
4. Not use this tool to access unauthorized content or services

Misuse of this tool may violate laws including but not limited to the Computer Fraud and Abuse Act, Digital Millennium Copyright Act, and equivalent legislation in other jurisdictions.
