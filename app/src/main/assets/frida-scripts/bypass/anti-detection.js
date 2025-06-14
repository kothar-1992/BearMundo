/**
 * Bear-Mod Anti-Detection Module
 * 
 * This script implements stealth techniques to avoid Frida detection.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Anti-Detection Module Loaded");

function setupAntiDetection() {
    console.log("[*] Setting up anti-detection measures");
    
    // Hide Frida process names
    try {
        const ps = Module.findExportByName(null, "ps");
        if (ps) {
            Interceptor.attach(ps, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        const output = Memory.readUtf8String(retval.toPointer());
                        if (output && output.includes("frida")) {
                            Memory.writeUtf8String(retval.toPointer(), output.replace(/frida\S*/g, "media_server"));
                        }
                    }
                }
            });
            console.log("[+] Hooked ps command");
        }
    } catch (e) {
        console.log("[-] Failed to hook ps command: " + e);
    }
    
    // Hide Frida strings in memory
    try {
        const strstr = Module.findExportByName(null, "strstr");
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function(args) {
                    const haystack = Memory.readUtf8String(args[0]);
                    const needle = Memory.readUtf8String(args[1]);
                    if (needle && (
                        needle.includes("frida") || 
                        needle.includes("gum") || 
                        needle.includes("gadget") || 
                        needle.includes("script"))) {
                        args[1] = Memory.allocUtf8String("dummy");
                    }
                }
            });
            console.log("[+] Hooked strstr function");
        }
    } catch (e) {
        console.log("[-] Failed to hook strstr function: " + e);
    }
    
    // Hide Frida related files
    try {
        const fopen = Module.findExportByName(null, "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    const path = Memory.readUtf8String(args[0]);
                    if (path && (
                        path.includes("/proc/") || 
                        path.includes("/sys/") || 
                        path.includes("frida") || 
                        path.includes("gum"))) {
                        this.shouldModify = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldModify && !retval.isNull()) {
                        retval.replace(ptr(0)); // Return NULL for suspicious files
                    }
                }
            });
            console.log("[+] Hooked fopen function");
        }
    } catch (e) {
        console.log("[-] Failed to hook fopen function: " + e);
    }
    
    // Hook Java-based detection methods
    Java.perform(function() {
        try {
            // Hook Runtime.exec to prevent detection commands
            const Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
                if (cmd.includes("su") || 
                    cmd.includes("which") || 
                    cmd.includes("frida") || 
                    cmd.includes("ps")) {
                    console.log("[+] Blocked suspicious command: " + cmd);
                    return this.exec("echo");
                }
                return this.exec(cmd);
            };
            console.log("[+] Hooked Runtime.exec");
            
            // Hook ProcessBuilder to prevent detection commands
            const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
            ProcessBuilder.start.implementation = function() {
                const cmd = this.command.value.toString();
                if (cmd.includes("su") || 
                    cmd.includes("which") || 
                    cmd.includes("frida") || 
                    cmd.includes("ps")) {
                    console.log("[+] Blocked suspicious ProcessBuilder command: " + cmd);
                    this.command.value = Java.array('java.lang.String', ['echo']);
                }
                return this.start();
            };
            console.log("[+] Hooked ProcessBuilder.start");
        } catch (e) {
            console.log("[-] Failed to hook Java detection methods: " + e);
        }
    });
    
    console.log("[*] Anti-detection measures in place");
}

// Export the function
module.exports = {
    setupAntiDetection: setupAntiDetection
};
