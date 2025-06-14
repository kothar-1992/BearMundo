/**
 * Bear-Mod Common Utilities
 *
 * This script provides common utility functions for Frida scripts.
 *
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Common Utilities Loaded");

// Logging utilities
const Log = {
    d: function(message) {
        console.log(`[D] ${message}`);
    },
    i: function(message) {
        console.log(`[I] ${message}`);
    },
    w: function(message) {
        console.log(`[W] ${message}`);
    },
    e: function(message) {
        console.log(`[E] ${message}`);
    },
    highlight: function(message) {
        console.log(`\n[*] ======== ${message} ========\n`);
    }
};

// Memory utilities
const MemoryUtils = {
    // Convert ArrayBuffer to hex string
    byteArrayToHex: function(arrayBuffer) {
        return Array.from(new Uint8Array(arrayBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    // Convert hex string to ASCII if printable, otherwise keep hex
    hexToAscii: function(hex) {
        let str = '';
        for (let i = 0; i < hex.length; i += 2) {
            const charCode = parseInt(hex.substr(i, 2), 16);
            if (charCode >= 32 && charCode <= 126) { // Printable ASCII
                str += String.fromCharCode(charCode);
            } else {
                return hex; // Not all printable, return original hex
            }
        }
        return str;
    },

    // Find pattern in memory
    findPattern: function(pattern, module) {
        const moduleObj = Process.findModuleByName(module);
        if (!moduleObj) {
            Log.e(`Module ${module} not found`);
            return null;
        }

        Log.i(`Searching for pattern in ${module}`);

        let results = [];
        Memory.scan(moduleObj.base, moduleObj.size, pattern, {
            onMatch: function(address, size) {
                results.push(address);
                Log.i(`Found pattern at ${address}`);
            },
            onComplete: function() {
                Log.i(`Pattern search completed, found ${results.length} matches`);
            }
        });

        return results;
    },

    // Read memory at address
    readMemory: function(address, size) {
        try {
            const buffer = Memory.readByteArray(ptr(address), size);
            return this.byteArrayToHex(buffer);
        } catch (e) {
            Log.e(`Failed to read memory at ${address}: ${e}`);
            return null;
        }
    },

    // Write memory at address
    writeMemory: function(address, bytes) {
        try {
            Memory.writeByteArray(ptr(address), bytes);
            return true;
        } catch (e) {
            Log.e(`Failed to write memory at ${address}: ${e}`);
            return false;
        }
    }
};

// Java utilities
const JavaUtils = {
    // Get current application context
    getContext: function() {
        let context = null;
        Java.perform(function() {
            context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        });
        return context;
    },

    // Get package name
    getPackageName: function() {
        let packageName = null;
        Java.perform(function() {
            packageName = JavaUtils.getContext().getPackageName();
        });
        return packageName;
    },

    // Get app version
    getAppVersion: function() {
        let version = null;
        Java.perform(function() {
            const context = JavaUtils.getContext();
            const packageManager = context.getPackageManager();
            const packageInfo = packageManager.getPackageInfo(context.getPackageName(), 0);
            version = packageInfo.versionName.value;
        });
        return version;
    },

    // Check if class exists
    classExists: function(className) {
        let exists = false;
        Java.perform(function() {
            try {
                Java.use(className);
                exists = true;
            } catch (e) {
                exists = false;
            }
        });
        return exists;
    }
};

// File system utilities
const FileUtils = {
    // Read file content
    readFile: function(path) {
        try {
            const file = new File(path, "r");
            const content = file.readAll();
            file.close();
            return content;
        } catch (e) {
            Log.e(`Failed to read file ${path}: ${e}`);
            return null;
        }
    },

    // Write content to file
    writeFile: function(path, content) {
        try {
            const file = new File(path, "w");
            file.write(content);
            file.close();
            return true;
        } catch (e) {
            Log.e(`Failed to write to file ${path}: ${e}`);
            return false;
        }
    },

    // Check if file exists
    fileExists: function(path) {
        try {
            const file = new File(path, "r");
            file.close();
            return true;
        } catch (e) {
            return false;
        }
    }
};

// Network utilities
const NetworkUtils = {
    // Parse URL
    parseUrl: function(url) {
        try {
            const URL = Java.use("java.net.URL");
            const urlObj = URL.$new(url);
            return {
                protocol: urlObj.getProtocol(),
                host: urlObj.getHost(),
                port: urlObj.getPort(),
                path: urlObj.getPath(),
                query: urlObj.getQuery()
            };
        } catch (e) {
            Log.e(`Failed to parse URL ${url}: ${e}`);
            return null;
        }
    },

    // Format HTTP request/response for logging
    formatHttpMessage: function(headers, body) {
        let result = "";

        // Format headers
        for (const key in headers) {
            result += `${key}: ${headers[key]}\n`;
        }

        // Add body if exists
        if (body) {
            result += "\n" + body;
        }

        return result;
    }
};

// Crypto utilities
const CryptoUtils = {
    // Get hash of data
    getHash: function(data, algorithm) {
        try {
            const MessageDigest = Java.use("java.security.MessageDigest");
            const digest = MessageDigest.getInstance(algorithm);
            const bytes = data instanceof Array ? data : Java.array('byte', data.split('').map(c => c.charCodeAt(0)));
            const hash = digest.digest(bytes);
            return MemoryUtils.byteArrayToHex(hash);
        } catch (e) {
            Log.e(`Failed to compute ${algorithm} hash: ${e}`);
            return null;
        }
    },

    // Get SHA-256 hash
    getSHA256: function(data) {
        return this.getHash(data, "SHA-256");
    },

    // Get MD5 hash
    getMD5: function(data) {
        return this.getHash(data, "MD5");
    }
};

// Export utilities
module.exports = {
    Log: Log,
    MemoryUtils: MemoryUtils,
    JavaUtils: JavaUtils,
    FileUtils: FileUtils,
    NetworkUtils: NetworkUtils,
    CryptoUtils: CryptoUtils
};
