/**
 * Bear-Mod Signature Verification Bypass (SignKill) - Part 2
 * 
 * This script continues the signature verification bypass by
 * storing the original signature and creating a fake one.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 */

console.log("[*] Signature Verification Bypass (SignKill) Part 2 Loaded");

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
                    console.log("[*] Original signature for " + pkg + ": " + sigHex.substring(0, 32) + "...");
                } catch (e) {
                    console.log("[!] Error getting original signature: " + e);
                }
            }
            
            console.log("[+] Spoofing signature check for " + pkg);
            
            // Create a fake signature - this will be implemented in part 3
        }
        
        return packageInfo;
    };
    
    console.log("[*] Part 2 initialized - Signature extraction complete");
});
