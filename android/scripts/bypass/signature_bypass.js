/**
 * Bear-Mod Signature Verification Bypass
 * 
 * This script bypasses signature verification by hooking into
 * the getPackageInfo method and returning a fake valid signature.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Signature Verification Bypass Loaded");

// Enable stealth mode by loading the anti-detection module
try {
    const antiDetection = require('../stealth/anti_detection.js');
    antiDetection.setupAntiDetection();
    console.log("[*] Anti-detection measures enabled");
} catch (e) {
    console.log("[!] Anti-detection module not available: " + e);
}

Java.perform(function() {
    console.log("[*] Java VM initialized");
    
    // Store original signatures for reporting
    var originalSignatures = {};
    
    // Hook ApplicationPackageManager.getPackageInfo
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {
        // Check if signature flag is set
        var GET_SIGNATURES = 64; // PackageManager.GET_SIGNATURES
        var checkingSignature = (flags & GET_SIGNATURES) != 0;
        
        // Get the original package info
        var packageInfo = this.getPackageInfo.call(this, pkg, flags);
        
        // Only modify if checking signatures
        if (checkingSignature && packageInfo.signatures) {
            // Store original signature for reporting if we haven't seen it before
            if (!originalSignatures[pkg] && packageInfo.signatures.value) {
                try {
                    var sigHex = "";
                    if (packageInfo.signatures.value.length > 0) {
                        sigHex = packageInfo.signatures.value[0].toByteArray().map(function(b) {
                            return ('0' + (b & 0xFF).toString(16)).slice(-2);
                        }).join('');
                    }
                    originalSignatures[pkg] = sigHex;
                } catch (e) {
                    console.log("[!] Error getting original signature: " + e);
                }
            }
            
            console.log("[+] Spoofing signature check for " + pkg);
            
            // Create a fake signature
            var Signature = Java.use("android.content.pm.Signature");
            var fakeSignature = Signature.$new("308203..."); // Insert real valid signature hex
            
            // Replace the signatures in the package info
            packageInfo.signatures.value = [fakeSignature];
            
            // Log the action
            console.log("[+] Signature spoofed for " + pkg);
        }
        
        return packageInfo;
    };
    
    // Also hook PackageManager.getPackageArchiveInfo for APK files
    try {
        PackageManager.getPackageArchiveInfo.overload("java.lang.String", "int").implementation = function(archivePath, flags) {
            // Check if signature flag is set
            var GET_SIGNATURES = 64; // PackageManager.GET_SIGNATURES
            var checkingSignature = (flags & GET_SIGNATURES) != 0;
            
            // Get the original package info
            var packageInfo = this.getPackageArchiveInfo.call(this, archivePath, flags);
            
            // Only modify if checking signatures and packageInfo exists
            if (checkingSignature && packageInfo && packageInfo.signatures) {
                console.log("[+] Spoofing archive signature check for " + archivePath);
                
                // Create a fake signature
                var Signature = Java.use("android.content.pm.Signature");
                var fakeSignature = Signature.$new("308203..."); // Insert real valid signature hex
                
                // Replace the signatures in the package info
                packageInfo.signatures.value = [fakeSignature];
                
                // Log the action
                console.log("[+] Archive signature spoofed for " + archivePath);
            }
            
            return packageInfo;
        };
        console.log("[+] PackageManager.getPackageArchiveInfo hooked");
    } catch (e) {
        console.log("[-] Failed to hook PackageManager.getPackageArchiveInfo: " + e);
    }
    
    // Hook signature verification in SignatureVerifier class if available
    try {
        var SignatureVerifier = Java.use("android.content.pm.SignatureVerifier");
        
        // Hook verifySignature method
        if (SignatureVerifier.verifySignature) {
            SignatureVerifier.verifySignature.implementation = function() {
                console.log("[+] SignatureVerifier.verifySignature bypassed");
                return true;
            };
            console.log("[+] SignatureVerifier.verifySignature hooked");
        }
    } catch (e) {
        console.log("[-] SignatureVerifier not found or failed to hook: " + e);
    }
    
    // Print a summary of original signatures at the end
    setTimeout(function() {
        console.log("\n[*] Original Signature Summary:");
        for (var pkg in originalSignatures) {
            console.log(`  ${pkg}: ${originalSignatures[pkg].substring(0, 32)}...`);
        }
    }, 5000);
    
    console.log("[*] Signature verification bypass complete");
});

console.log("[*] Signature verification bypass script initialized");
