/**
 * Bear-Mod App Analyzer
 *
 * This script analyzes an Android application to identify:
 * - Security mechanisms
 * - Network communication
 * - Native libraries
 * - Interesting classes and methods
 *
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] App Analyzer Loaded");

// Setup logging and utilities
let Log, MemoryUtils, JavaUtils;

// Import common utilities
try {
    const common = require('../utils/common.js');
    Log = common.Log;
    MemoryUtils = common.MemoryUtils;
    JavaUtils = common.JavaUtils;
} catch (e) {
    console.log("[!] Common utilities not available: " + e);
    // Define basic logging if common utilities are not available
    Log = {
        d: function(message) { console.log(`[D] ${message}`); },
        i: function(message) { console.log(`[I] ${message}`); },
        w: function(message) { console.log(`[W] ${message}`); },
        e: function(message) { console.log(`[E] ${message}`); },
        highlight: function(message) { console.log(`\n[*] ======== ${message} ========\n`); }
    };
}

// Enable stealth mode by loading the anti-detection module
try {
    const antiDetection = require('../stealth/anti_detection.js');
    antiDetection.setupAntiDetection();
    Log.i("Anti-detection measures enabled");
} catch (e) {
    Log.w("Anti-detection module not available: " + e);
}

// Load configuration
let analysisConfig;
try {
    // Try to load external configuration
    const mainConfig = require('../../config.js');
    analysisConfig = mainConfig.analysis || {};
    Log.i("Loaded analysis configuration from external config");
} catch (e) {
    Log.w("External configuration not found, using default analysis configuration");

    // Default configuration
    analysisConfig = {
        logLevel: "info",  // debug, info, warn, error
        traceNativeCalls: true,
        monitorNetwork: true,
        monitorFileAccess: true,
        monitorCrypto: true,
        monitorClasses: [
            "security",
            "crypto",
            "network",
            "http",
            "socket",
            "ssl",
            "tls",
            "cert"
        ]
    };
}

// Analysis state
const state = {
    securityMechanisms: [],
    nativeLibraries: [],
    networkCalls: [],
    fileAccess: [],
    cryptoOperations: [],
    interestingClasses: []
};

// Main initialization
function initialize() {
    Log.highlight("App Analyzer Starting");

    // Hook Java methods when Java VM is available
    if (Java.available) {
        Java.perform(analyzeJavaCode);
    } else {
        Log.e("Java is not available");
    }

    // Hook native functions
    if (config.traceNativeCalls) {
        analyzeNativeCode();
    }

    Log.highlight("App Analyzer Initialized");
}

// Analyze Java code
function analyzeJavaCode() {
    Log.i("Analyzing Java code");

    // Get app information
    Java.perform(function() {
        try {
            const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            const packageName = context.getPackageName();
            const packageManager = context.getPackageManager();
            const packageInfo = packageManager.getPackageInfo(packageName, 0);
            const appVersion = packageInfo.versionName.value;

            Log.highlight(`Analyzing app: ${packageName} (version ${appVersion})`);
        } catch (e) {
            Log.e("Failed to get app information: " + e);
        }
    });

    // Monitor class loading
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Check if this is an interesting class
            let isInteresting = false;

            // Check if class name contains any of the monitored keywords
            for (const keyword of config.monitorClasses) {
                if (className.toLowerCase().includes(keyword)) {
                    isInteresting = true;
                    break;
                }
            }

            // If this is an interesting class, analyze it
            if (isInteresting) {
                Log.i(`Found interesting class: ${className}`);

                try {
                    analyzeClass(className);
                } catch (e) {
                    Log.d(`Could not analyze class ${className}: ${e}`);
                }
            }
        },
        onComplete: function() {
            Log.i("Class enumeration completed");
        }
    });

    // Monitor System.loadLibrary calls
    const System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function(libraryName) {
        Log.highlight(`Loading native library: ${libraryName}`);

        // Add to state
        state.nativeLibraries.push({
            name: libraryName,
            time: new Date().getTime()
        });

        // Call original implementation
        this.loadLibrary(libraryName);

        Log.i(`Library ${libraryName} loaded successfully`);
    };

    // Monitor network activity
    if (config.monitorNetwork) {
        monitorNetwork();
    }

    // Monitor file access
    if (config.monitorFileAccess) {
        monitorFileAccess();
    }

    // Monitor crypto operations
    if (config.monitorCrypto) {
        monitorCrypto();
    }

    // Check for root detection
    checkForRootDetection();

    // Check for SSL pinning
    checkForSSLPinning();
}

// Analyze a specific class
function analyzeClass(className) {
    try {
        const javaClass = Java.use(className);
        const methods = javaClass.class.getDeclaredMethods();

        Log.d(`Analyzing class ${className} with ${methods.length} methods`);

        // Add to state
        state.interestingClasses.push({
            name: className,
            methods: []
        });

        // Analyze methods
        for (let i = 0; i < methods.length; i++) {
            const method = methods[i];
            const methodName = method.getName();

            // Skip common methods
            if (methodName === "$init" ||
                methodName === "toString" ||
                methodName === "hashCode" ||
                methodName === "equals") {
                continue;
            }

            // Add to state
            state.interestingClasses[state.interestingClasses.length - 1].methods.push(methodName);

            Log.d(`Found method: ${className}.${methodName}`);

            // Hook interesting methods
            if (methodName.includes("check") ||
                methodName.includes("verify") ||
                methodName.includes("validate") ||
                methodName.includes("encrypt") ||
                methodName.includes("decrypt") ||
                methodName.includes("sign") ||
                methodName.includes("authenticate")) {

                try {
                    if (javaClass[methodName] && javaClass[methodName].overloads.length > 0) {
                        javaClass[methodName].overloads[0].implementation = function() {
                            Log.i(`Called ${className}.${methodName}`);

                            // Call original implementation with arguments
                            const result = this[methodName].apply(this, arguments);

                            Log.i(`${className}.${methodName} returned: ${result}`);
                            return result;
                        };

                        Log.d(`Hooked ${className}.${methodName}`);
                    }
                } catch (e) {
                    Log.d(`Could not hook ${className}.${methodName}: ${e}`);
                }
            }
        }
    } catch (e) {
        Log.e(`Failed to analyze class ${className}: ${e}`);
    }
}

// Analyze native code
function analyzeNativeCode() {
    Log.i("Analyzing native code");

    // Hook dlopen to detect library loading
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            const path = Memory.readUtf8String(args[0]);
            this.path = path;
            Log.i(`dlopen called with path: ${path}`);
        },
        onLeave: function(retval) {
            Log.i(`dlopen for ${this.path} returned: ${retval}`);

            // Add to state
            state.nativeLibraries.push({
                name: this.path,
                handle: retval,
                time: new Date().getTime()
            });
        }
    });

    // Hook socket functions
    const socketFunctions = [
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "send",
        "recv",
        "sendto",
        "recvfrom"
    ];

    for (const funcName of socketFunctions) {
        const funcPtr = Module.findExportByName(null, funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args) {
                    Log.i(`${funcName} called`);
                    this.args = args;
                },
                onLeave: function(retval) {
                    Log.i(`${funcName} returned: ${retval}`);
                }
            });

            Log.d(`Hooked ${funcName}`);
        }
    }

    // Hook SSL functions
    const sslFunctions = [
        "SSL_connect",
        "SSL_accept",
        "SSL_write",
        "SSL_read",
        "SSL_get_verify_result",
        "SSL_CTX_set_verify"
    ];

    for (const funcName of sslFunctions) {
        const funcPtr = Module.findExportByName(null, funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args) {
                    Log.i(`${funcName} called`);
                    this.args = args;
                },
                onLeave: function(retval) {
                    Log.i(`${funcName} returned: ${retval}`);
                }
            });

            Log.d(`Hooked ${funcName}`);
        }
    }
}

// Monitor network activity
function monitorNetwork() {
    Log.i("Setting up network monitoring");

    // Hook URL connection
    try {
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            const url = this.toString();
            Log.i(`Opening connection to: ${url}`);

            // Add to state
            state.networkCalls.push({
                url: url,
                type: "URL.openConnection",
                time: new Date().getTime()
            });

            return this.openConnection();
        };

        // Hook HttpURLConnection
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.connect.implementation = function() {
            const url = this.getURL().toString();
            const method = this.getRequestMethod();
            Log.i(`HTTP ${method} request to ${url}`);

            // Add to state
            state.networkCalls.push({
                url: url,
                method: method,
                type: "HttpURLConnection",
                time: new Date().getTime()
            });

            this.connect();
        };

        // Hook OkHttp if available
        try {
            const OkHttpClient = Java.use("okhttp3.OkHttpClient");
            const Request = Java.use("okhttp3.Request");

            OkHttpClient.newCall.overload("okhttp3.Request").implementation = function(request) {
                const url = request.url().toString();
                const method = request.method();
                Log.i(`OkHttp ${method} request to ${url}`);

                // Add to state
                state.networkCalls.push({
                    url: url,
                    method: method,
                    type: "OkHttp",
                    time: new Date().getTime()
                });

                return this.newCall(request);
            };
        } catch (e) {
            Log.d("OkHttp not found or failed to hook");
        }

        Log.i("Network hooks installed");
    } catch (e) {
        Log.e(`Failed to hook network calls: ${e}`);
    }
}

// Monitor file access
function monitorFileAccess() {
    Log.i("Setting up file access monitoring");

    try {
        // Hook FileInputStream
        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.io.File").implementation = function(file) {
            const path = file.getAbsolutePath();
            Log.i(`Reading file: ${path}`);

            // Add to state
            state.fileAccess.push({
                path: path,
                operation: "read",
                time: new Date().getTime()
            });

            return this.$init(file);
        };

        // Hook FileOutputStream
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function(file, append) {
            const path = file.getAbsolutePath();
            Log.i(`Writing file: ${path} (append: ${append})`);

            // Add to state
            state.fileAccess.push({
                path: path,
                operation: "write",
                append: append,
                time: new Date().getTime()
            });

            return this.$init(file, append);
        };

        Log.i("File access hooks installed");
    } catch (e) {
        Log.e(`Failed to hook file access: ${e}`);
    }
}

// Monitor crypto operations
function monitorCrypto() {
    Log.i("Setting up crypto monitoring");

    try {
        // Hook Cipher
        const Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            Log.i(`Cipher.getInstance called with transformation: ${transformation}`);

            // Add to state
            state.cryptoOperations.push({
                type: "Cipher",
                algorithm: transformation,
                time: new Date().getTime()
            });

            return this.getInstance(transformation);
        };

        Cipher.doFinal.overload("[B").implementation = function(input) {
            Log.i(`Cipher.doFinal called with ${input.length} bytes of data`);

            // Call original implementation
            const result = this.doFinal(input);

            Log.i(`Cipher.doFinal returned ${result.length} bytes of data`);
            return result;
        };

        // Hook MessageDigest
        const MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            Log.i(`MessageDigest.getInstance called with algorithm: ${algorithm}`);

            // Add to state
            state.cryptoOperations.push({
                type: "MessageDigest",
                algorithm: algorithm,
                time: new Date().getTime()
            });

            return this.getInstance(algorithm);
        };

        // Hook KeyGenerator
        const KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            Log.i(`KeyGenerator.getInstance called with algorithm: ${algorithm}`);

            // Add to state
            state.cryptoOperations.push({
                type: "KeyGenerator",
                algorithm: algorithm,
                time: new Date().getTime()
            });

            return this.getInstance(algorithm);
        };

        Log.i("Crypto hooks installed");
    } catch (e) {
        Log.e(`Failed to hook crypto operations: ${e}`);
    }
}

// Check for root detection
function checkForRootDetection() {
    Log.i("Checking for root detection");

    // Common root detection classes
    const rootDetectionClasses = [
        "RootBeer",
        "RootChecker",
        "RootDetector",
        "RootTools",
        "RootManager"
    ];

    // Check if any of these classes are loaded
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            for (const rootClass of rootDetectionClasses) {
                if (className.includes(rootClass)) {
                    Log.highlight(`Found root detection class: ${className}`);

                    // Add to state
                    state.securityMechanisms.push({
                        type: "root_detection",
                        class: className,
                        time: new Date().getTime()
                    });

                    break;
                }
            }
        },
        onComplete: function() {
            Log.i("Root detection check completed");
        }
    });
}

// Check for SSL pinning
function checkForSSLPinning() {
    Log.i("Checking for SSL pinning");

    // Common SSL pinning classes
    const sslPinningClasses = [
        "CertificatePinner",
        "PinningTrustManager",
        "SSLCertificateChecker",
        "TrustKit"
    ];

    // Check if any of these classes are loaded
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            for (const sslClass of sslPinningClasses) {
                if (className.includes(sslClass)) {
                    Log.highlight(`Found SSL pinning class: ${className}`);

                    // Add to state
                    state.securityMechanisms.push({
                        type: "ssl_pinning",
                        class: className,
                        time: new Date().getTime()
                    });

                    break;
                }
            }
        },
        onComplete: function() {
            Log.i("SSL pinning check completed");
        }
    });
}

// Print analysis report
function printReport() {
    Log.highlight("Analysis Report");

    // Security mechanisms
    Log.i(`Security Mechanisms: ${state.securityMechanisms.length}`);
    for (const mechanism of state.securityMechanisms) {
        Log.i(`  - Type: ${mechanism.type}`);
        for (const key in mechanism) {
            if (key !== "type" && key !== "time") {
                Log.i(`    ${key}: ${mechanism[key]}`);
            }
        }
    }

    // Native libraries
    Log.i(`Native Libraries: ${state.nativeLibraries.length}`);
    for (const lib of state.nativeLibraries) {
        Log.i(`  - ${lib.name}`);
    }

    // Network calls
    Log.i(`Network Calls: ${state.networkCalls.length}`);
    for (const call of state.networkCalls) {
        Log.i(`  - ${call.type} ${call.method || 'GET'} ${call.url}`);
    }

    // File access
    Log.i(`File Access: ${state.fileAccess.length}`);
    for (const access of state.fileAccess) {
        Log.i(`  - ${access.operation} ${access.path}`);
    }

    // Crypto operations
    Log.i(`Crypto Operations: ${state.cryptoOperations.length}`);
    for (const op of state.cryptoOperations) {
        Log.i(`  - ${op.type} ${op.algorithm}`);
    }

    // Interesting classes
    Log.i(`Interesting Classes: ${state.interestingClasses.length}`);
    for (const cls of state.interestingClasses) {
        Log.i(`  - ${cls.name}`);
        if (cls.methods.length > 0) {
            Log.i(`    Methods: ${cls.methods.length}`);
            for (let i = 0; i < Math.min(5, cls.methods.length); i++) {
                Log.i(`      - ${cls.methods[i]}`);
            }
            if (cls.methods.length > 5) {
                Log.i(`      - ... and ${cls.methods.length - 5} more`);
            }
        }
    }

    Log.highlight("End of Analysis Report");
}

// Set up a timer to print the report periodically
setTimeout(printReport, 10000); // Print after 10 seconds

// Start the script
initialize();
