/**
 * Bear-Mod Root Detection Bypass
 * 
 * This script bypasses common root detection methods by hooking
 * functions that check for root access and returning false.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Root Detection Bypass Loaded");

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
    
    // Dynamic class discovery
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("Security") || 
                className.includes("Root") || 
                className.includes("Emulator") || 
                className.includes("Debug")) {
                
                try {
                    var classObj = Java.use(className);
                    
                    // Find methods that might be root checks
                    for (var method of classObj.class.getDeclaredMethods()) {
                        var methodName = method.getName();
                        
                        // Check if method name suggests a root check
                        if (methodName.includes("isRoot") || 
                            methodName.includes("checkRoot") || 
                            methodName.includes("detectRoot") ||
                            methodName.includes("hasRoot") ||
                            methodName.includes("isRooted") ||
                            methodName.includes("isSuperUser") ||
                            methodName.includes("isEmulator") ||
                            methodName.includes("isDebuggable")) {
                            
                            console.log("[+] Found potential root check: " + className + "." + methodName);
                            
                            // Hook the method if it returns boolean
                            if (method.getReturnType().getName() === "boolean") {
                                try {
                                    classObj[methodName].implementation = function() {
                                        console.log("[+] Bypassed root check: " + className + "." + methodName);
                                        return false;
                                    };
                                    console.log("[+] Successfully hooked: " + className + "." + methodName);
                                } catch (e) {
                                    console.log("[-] Failed to hook method: " + e);
                                }
                            }
                        }
                    }
                } catch (e) {
                    // Skip if we can't access this class
                }
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration completed");
        }
    });
    
    // Hook specific known root detection methods
    
    // RootBeer
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log("[+] Bypassed RootBeer.isRooted()");
            return false;
        };
        console.log("[+] RootBeer hooks installed");
    } catch (e) {
        console.log("[-] RootBeer not found");
    }
    
    // File-based checks
    var commonRootFiles = [
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/system/su",
        "/system/bin/.ext/.su",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/system/xbin/busybox"
    ];
    
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var fileName = this.getAbsolutePath();
        
        // Check if this is a root-related file
        for (var i = 0; i < commonRootFiles.length; i++) {
            if (fileName === commonRootFiles[i]) {
                console.log("[+] Bypassed file check: " + fileName);
                return false;
            }
        }
        
        // Call the original method for non-root files
        return this.exists();
    };
    console.log("[+] File.exists() hooked");
    
    // Runtime.exec checks for "su" command
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.toLowerCase().indexOf("su") !== -1) {
            console.log("[+] Bypassed Runtime.exec check for su: " + cmd);
            throw new Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec(cmd);
    };
    console.log("[+] Runtime.exec() hooked");
    
    // ProcessBuilder checks
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.value.toString();
        if (cmd.toLowerCase().indexOf("su") !== -1) {
            console.log("[+] Bypassed ProcessBuilder check for su: " + cmd);
            throw new Java.use("java.io.IOException").$new("Command not found");
        }
        return this.start();
    };
    console.log("[+] ProcessBuilder.start() hooked");
    
    console.log("[*] Root detection bypass complete");
});

// Hook native methods if needed
Interceptor.attach(Module.findExportByName(null, "fopen"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        this.path = path;
        
        // Check if this is a root-related file
        if (path.indexOf("su") !== -1 || 
            path.indexOf("magisk") !== -1 || 
            path.indexOf("supersu") !== -1) {
            console.log("[+] Bypassed native fopen check: " + path);
            args[0] = Memory.allocUtf8String("/system/nonexistent_file");
        }
    },
    onLeave: function(retval) {
        if (this.path && (
            this.path.indexOf("su") !== -1 || 
            this.path.indexOf("magisk") !== -1 || 
            this.path.indexOf("supersu") !== -1)) {
            retval.replace(0); // NULL pointer
        }
    }
});

console.log("[*] Root detection bypass script initialized");
