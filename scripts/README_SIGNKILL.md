# Signature Verification Bypass (SignKill)

This directory contains Frida scripts for bypassing signature verification in Android applications.

## Overview

Many Android apps check if they've been modified by verifying their signature. These scripts bypass this protection by hooking into the signature verification process and returning fake valid signatures.

## Available Scripts

1. **bypass-signkill.js**: Complete implementation that hooks all signature verification methods
2. **bypass-signkill_1.js**: Part 1 - Basic hook setup
3. **bypass-signkill_2.js**: Part 2 - Signature extraction
4. **bypass-signkill_3.js**: Part 3 - Signature replacement
5. **bypass-signkill_4.js**: Part 4 - Additional verification bypasses

## How It Works

The scripts work by:

1. Hooking `ApplicationPackageManager.getPackageInfo()` which is used to retrieve package information including signatures
2. Storing the original signature for reference
3. Creating a fake signature to replace the original
4. Replacing the signature in the returned package info
5. Additionally hooking other signature verification methods for comprehensive bypass

## Usage

### Basic Usage

```bash
# Using the Frida launcher
python ../tools/frida_launcher.py run -p com.example.app -s bypass-signkill.js

# Or directly with Frida
frida -U -n com.example.app -l bypass-signkill.js --no-pause
```

### Advanced Usage

For educational purposes, you can use the individual parts to understand how the bypass works:

```bash
# Part 1: Basic hook setup
frida -U -n com.example.app -l bypass-signkill_1.js --no-pause

# Part 2: Signature extraction
frida -U -n com.example.app -l bypass-signkill_2.js --no-pause

# Part 3: Signature replacement
frida -U -n com.example.app -l bypass-signkill_3.js --no-pause

# Part 4: Additional verification bypasses
frida -U -n com.example.app -l bypass-signkill_4.js --no-pause
```

## Customization

To customize the script for a specific app:

1. Extract the original signature from the app:
   ```bash
   # Run the script with logging enabled
   frida -U -n com.example.app -l bypass-signkill.js --no-pause
   ```

2. Note the original signature printed in the console

3. Replace the fake signature in the script with the original signature:
   ```javascript
   // Replace this line
   var fakeSignature = Signature.$new("308203...");
   
   // With the actual signature from the app
   var fakeSignature = Signature.$new("YOUR_EXTRACTED_SIGNATURE");
   ```

## Technical Details

The script hooks into several key methods:

1. `ApplicationPackageManager.getPackageInfo()`: Main method for retrieving package signatures
2. `PackageManager.getPackageArchiveInfo()`: Used for verifying APK files
3. `SignatureVerifier.verifySignature()`: Used for direct signature verification

When an app checks its signature, these hooks intercept the call and return a valid signature, making the app believe it hasn't been modified.

## DISCLAIMER

Bear-Mod is designed for security researchers, app developers, and educational purposes only.
Users must:
1. Only analyze applications they own or have explicit permission to test
2. Respect intellectual property rights and terms of service
3. Use findings responsibly through proper disclosure channels
4. Not use this tool to access unauthorized content or services

Misuse of this tool may violate laws including but not limited to the Computer Fraud and Abuse Act, Digital Millennium Copyright Act, and equivalent legislation in other jurisdictions.
