/**
 * SDK Analyzer - Specialized Frida script for analyzing the SDK in BearMod
 * 
 * This script focuses specifically on SDK-related functionality:
 * - Tracking SDK initialization
 * - Monitoring SDK function calls
 * - Analyzing SDK memory usage
 * - Intercepting SDK network communication
 */

// Configuration
const config = {
    debug: true,
    dumpMemory: false,  // Set to true to dump memory regions (can be large)
    trackAllocations: true,
    interceptNetwork: true,
    logLevel: 'info',   // 'debug', 'info', 'warn', 'error'
    sdkLibraryName: "libbearmod.so",
    sdkClassPrefix: "com.bearmod"
};

// Logging utilities
const Log = {
    d: function(message) {
        if (config.logLevel === 'debug' || config.debug) {
            console.log(`[D] ${message}`);
        }
    },
    i: function(message) {
        if (config.logLevel === 'debug' || config.logLevel === 'info' || config.debug) {
            console.log(`[I] ${message}`);
        }
    },
    w: function(message) {
        if (config.logLevel === 'debug' || config.logLevel === 'info' || config.logLevel === 'warn' || config.debug) {
            console.log(`[W] ${message}`);
        }
    },
    e: function(message) {
        console.log(`[E] ${message}`);
    },
    highlight: function(message) {
        console.log(`\n[*] ======== ${message} ========\n`);
    }
};

// SDK Analysis state
const sdkState = {
    initialized: false,
    initializationTime: 0,
    memoryUsage: 0,
    functionCalls: {},
    networkRequests: [],
    memoryAllocations: []
};

// Main initialization
function initialize() {
    Log.highlight("SDK Analyzer Starting");
    
    // Hook Java methods when Java VM is available
    if (Java.available) {
        Java.perform(analyzeSDKJava);
    } else {
        Log.e("Java is not available");
    }
    
    // Hook native functions
    analyzeSDKNative();
    
    Log.highlight("SDK Analyzer Initialized");
}

// Analyze SDK Java components
function analyzeSDKJava() {
    Log.i("Analyzing SDK Java components");
    
    // Hook SDK initialization
    try {
        // Look for NativeUtils or similar class that might initialize the SDK
        const possibleInitClasses = [
            "com.bearmod.NativeUtils",
            "com.bearmod.sdk.SDKManager",
            "com.bearmod.MinimalSDK",
            "com.bearmod.MainActivity"
        ];
        
        for (const className of possibleInitClasses) {
            try {
                const ClassObj = Java.use(className);
                
                // Look for initialize method
                if (ClassObj.initialize) {
                    ClassObj.initialize.overloads.forEach(function(overload) {
                        overload.implementation = function() {
                            Log.highlight(`SDK initialization detected in ${className}.initialize`);
                            sdkState.initializationTime = new Date().getTime();
                            
                            // Call original implementation
                            const result = this.initialize.apply(this, arguments);
                            
                            sdkState.initialized = true;
                            Log.i(`SDK initialized in ${new Date().getTime() - sdkState.initializationTime}ms`);
                            
                            return result;
                        };
                    });
                    
                    Log.i(`Hooked ${className}.initialize`);
                }
                
                // Look for other potential initialization methods
                const initMethodNames = ["init", "setup", "start", "onCreate", "onResume"];
                for (const methodName of initMethodNames) {
                    if (ClassObj[methodName]) {
                        ClassObj[methodName].overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                Log.i(`Potential SDK initialization: ${className}.${methodName}`);
                                
                                // Call original implementation
                                const result = this[methodName].apply(this, arguments);
                                
                                return result;
                            };
                        });
                        
                        Log.i(`Hooked ${className}.${methodName}`);
                    }
                }
            } catch (e) {
                Log.d(`Class ${className} not found or failed to hook: ${e}`);
            }
        }
    } catch (e) {
        Log.e(`Failed to hook SDK initialization: ${e}`);
    }
    
    // Monitor System.loadLibrary calls to detect SDK native library loading
    const System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function(libraryName) {
        Log.i(`Loading native library: ${libraryName}`);
        
        // Call original implementation
        this.loadLibrary(libraryName);
        
        // If it's our target library, analyze it
        if (libraryName === "bearmod" || libraryName.includes("sdk")) {
            Log.highlight(`SDK native library loaded: ${libraryName}`);
            
            setTimeout(function() {
                analyzeSDKLibrary(libraryName);
            }, 500); // Give it some time to load
        }
        
        Log.i(`Library ${libraryName} loaded successfully`);
    };
    
    // Find and analyze SDK classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.startsWith(config.sdkClassPrefix) || 
                className.includes("sdk") || 
                className.includes("SDK")) {
                
                Log.i(`Found SDK class: ${className}`);
                
                // Try to analyze the class
                try {
                    analyzeSDKClass(className);
                } catch (e) {
                    Log.d(`Could not analyze class ${className}: ${e}`);
                }
            }
        },
        onComplete: function() {
            Log.i("SDK class enumeration completed");
        }
    });
    
    // Monitor SDK network activity
    if (config.interceptNetwork) {
        monitorSDKNetwork();
    }
}

// Analyze SDK native components
function analyzeSDKNative() {
    Log.i("Analyzing SDK native components");
    
    // Hook dlopen to detect SDK library loading
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            const path = Memory.readUtf8String(args[0]);
            this.path = path;
            
            if (path && (path.includes("libbearmod.so") || path.includes("libsdk"))) {
                Log.highlight(`SDK library being loaded: ${path}`);
            }
        },
        onLeave: function(retval) {
            if (this.path && (this.path.includes("libbearmod.so") || this.path.includes("libsdk"))) {
                Log.i(`SDK library loaded: ${this.path}, handle: ${retval}`);
                
                setTimeout(function() {
                    const libName = this.path.split("/").pop();
                    analyzeSDKLibrary(libName);
                }.bind(this), 500); // Give it some time to load
            }
        }
    });
    
    // Track memory allocations if enabled
    if (config.trackAllocations) {
        const malloc = Module.findExportByName(null, "malloc");
        if (malloc) {
            Interceptor.attach(malloc, {
                onEnter: function(args) {
                    this.size = args[0].toInt32();
                },
                onLeave: function(retval) {
                    if (this.size > 1024 * 1024) { // Only track allocations > 1MB
                        sdkState.memoryUsage += this.size;
                        
                        // Get stack trace
                        const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress)
                            .filter(symbol => symbol.name && (
                                symbol.name.includes("sdk") || 
                                symbol.name.includes("bearmod")
                            ));
                        
                        if (backtrace.length > 0) {
                            // This is likely an SDK allocation
                            sdkState.memoryAllocations.push({
                                address: retval,
                                size: this.size,
                                time: new Date().getTime(),
                                backtrace: backtrace.map(symbol => symbol.name)
                            });
                            
                            Log.i(`SDK allocated ${this.size} bytes at ${retval}`);
                        }
                    }
                }
            });
        }
        
        const free = Module.findExportByName(null, "free");
        if (free) {
            Interceptor.attach(free, {
                onEnter: function(args) {
                    this.address = args[0];
                    
                    // Check if this is an SDK allocation
                    const allocation = sdkState.memoryAllocations.find(a => a.address.equals(this.address));
                    if (allocation) {
                        sdkState.memoryUsage -= allocation.size;
                        Log.i(`SDK freed ${allocation.size} bytes at ${this.address}`);
                        
                        // Remove from tracking
                        sdkState.memoryAllocations = sdkState.memoryAllocations.filter(
                            a => !a.address.equals(this.address)
                        );
                    }
                }
            });
        }
    }
}

// Analyze a specific SDK library
function analyzeSDKLibrary(libraryName) {
    Log.highlight(`Analyzing SDK library: ${libraryName}`);
    
    const libName = libraryName.includes(".so") ? libraryName : `lib${libraryName}.so`;
    const module = Process.findModuleByName(libName);
    
    if (!module) {
        Log.e(`Module ${libName} not found`);
        return;
    }
    
    Log.i(`Found ${libName} at base address: ${module.base}, size: ${module.size}`);
    
    // Enumerate exports
    const exports = module.enumerateExports();
    Log.i(`Found ${exports.length} exported functions`);
    
    // Track interesting exports
    const interestingExports = [];
    
    exports.forEach(exp => {
        if (exp.type === 'function') {
            Log.d(`Export: ${exp.name} at ${exp.address}`);
            
            // Check if this is an interesting function
            const isInteresting = 
                exp.name.includes("JNI_") || 
                exp.name.includes("Java_") || 
                exp.name.includes("init") || 
                exp.name.includes("SDK") || 
                exp.name.includes("setup");
            
            if (isInteresting) {
                interestingExports.push(exp);
                
                // Hook the function
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        Log.i(`Called SDK function: ${exp.name}`);
                        
                        // Track function call
                        if (!sdkState.functionCalls[exp.name]) {
                            sdkState.functionCalls[exp.name] = {
                                count: 0,
                                lastCalled: 0
                            };
                        }
                        
                        sdkState.functionCalls[exp.name].count++;
                        sdkState.functionCalls[exp.name].lastCalled = new Date().getTime();
                        
                        this.startTime = new Date().getTime();
                    },
                    onLeave: function(retval) {
                        const duration = new Date().getTime() - this.startTime;
                        Log.i(`SDK function ${exp.name} returned: ${retval} (took ${duration}ms)`);
                    }
                });
                
                Log.i(`Hooked SDK function: ${exp.name}`);
            }
        }
    });
    
    Log.i(`Found ${interestingExports.length} interesting SDK functions`);
    
    // Enumerate symbols for more information
    const symbols = module.enumerateSymbols();
    Log.i(`Found ${symbols.length} symbols`);
    
    // Look for interesting symbols
    symbols.forEach(sym => {
        if (sym.name.includes("SDK") || 
            sym.name.includes("Init") || 
            sym.name.includes("setup")) {
            
            Log.i(`Interesting symbol: ${sym.name} at ${sym.address}`);
        }
    });
    
    // Dump memory regions if enabled
    if (config.dumpMemory) {
        Log.i("Dumping memory regions...");
        
        Process.enumerateRanges('r--').forEach(range => {
            if (range.base >= module.base && 
                range.base.add(range.size) <= module.base.add(module.size)) {
                
                Log.i(`Memory region: ${range.base} - ${range.size} bytes`);
                
                // Try to dump strings from this region
                try {
                    const bytes = Memory.readByteArray(range.base, Math.min(range.size, 4096));
                    const view = new Uint8Array(bytes);
                    
                    let strings = [];
                    let currentString = "";
                    
                    for (let i = 0; i < view.length; i++) {
                        if (view[i] >= 32 && view[i] <= 126) { // Printable ASCII
                            currentString += String.fromCharCode(view[i]);
                        } else if (currentString.length >= 4) { // End of string
                            strings.push(currentString);
                            currentString = "";
                        } else {
                            currentString = "";
                        }
                    }
                    
                    if (currentString.length >= 4) {
                        strings.push(currentString);
                    }
                    
                    if (strings.length > 0) {
                        Log.i(`Found ${strings.length} strings in memory region`);
                        strings.forEach(str => {
                            if (str.includes("sdk") || 
                                str.includes("SDK") || 
                                str.includes("bearmod") || 
                                str.includes("config") || 
                                str.includes("init")) {
                                
                                Log.i(`Interesting string: ${str}`);
                            }
                        });
                    }
                } catch (e) {
                    Log.d(`Failed to dump memory region: ${e}`);
                }
            }
        });
    }
}

// Analyze a specific SDK class
function analyzeSDKClass(className) {
    try {
        const javaClass = Java.use(className);
        const methods = javaClass.class.getDeclaredMethods();
        
        Log.i(`Analyzing class ${className} with ${methods.length} methods`);
        
        // Track interesting methods
        const interestingMethods = [];
        
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
            
            // Check if this is an interesting method
            const isInteresting = 
                methodName.includes("init") || 
                methodName.includes("setup") || 
                methodName.includes("config") || 
                methodName.includes("start") || 
                methodName.includes("create") || 
                methodName.includes("load") || 
                methodName.includes("get") || 
                methodName.includes("set");
            
            if (isInteresting) {
                interestingMethods.push(methodName);
                
                // Try to hook the method
                try {
                    if (javaClass[methodName] && javaClass[methodName].overloads.length > 0) {
                        javaClass[methodName].overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                Log.i(`Called SDK method: ${className}.${methodName}`);
                                
                                // Track function call
                                const fullMethodName = `${className}.${methodName}`;
                                if (!sdkState.functionCalls[fullMethodName]) {
                                    sdkState.functionCalls[fullMethodName] = {
                                        count: 0,
                                        lastCalled: 0
                                    };
                                }
                                
                                sdkState.functionCalls[fullMethodName].count++;
                                sdkState.functionCalls[fullMethodName].lastCalled = new Date().getTime();
                                
                                const startTime = new Date().getTime();
                                
                                // Call original implementation
                                const result = this[methodName].apply(this, arguments);
                                
                                const duration = new Date().getTime() - startTime;
                                Log.i(`SDK method ${className}.${methodName} returned: ${result} (took ${duration}ms)`);
                                
                                return result;
                            };
                        });
                        
                        Log.i(`Hooked SDK method: ${className}.${methodName}`);
                    }
                } catch (e) {
                    Log.d(`Could not hook ${className}.${methodName}: ${e}`);
                }
            }
        }
        
        Log.i(`Found ${interestingMethods.length} interesting methods in ${className}`);
        
        // Analyze fields
        const fields = javaClass.class.getDeclaredFields();
        Log.i(`Class ${className} has ${fields.length} fields`);
        
        for (let i = 0; i < fields.length; i++) {
            const field = fields[i];
            const fieldName = field.getName();
            
            // Check if this is an interesting field
            const isInteresting = 
                fieldName.includes("sdk") || 
                fieldName.includes("config") || 
                fieldName.includes("instance") || 
                fieldName.includes("manager") || 
                fieldName.includes("initialized");
            
            if (isInteresting) {
                Log.i(`Interesting field: ${className}.${fieldName}`);
                
                // Try to get field value
                try {
                    field.setAccessible(true);
                    
                    // This is a simplified approach and might not work for all fields
                    const instance = javaClass.class.newInstance();
                    const value = field.get(instance);
                    
                    Log.i(`Field ${className}.${fieldName} value: ${value}`);
                } catch (e) {
                    Log.d(`Could not get field value: ${e}`);
                }
            }
        }
    } catch (e) {
        Log.e(`Failed to analyze class ${className}: ${e}`);
    }
}

// Monitor SDK network activity
function monitorSDKNetwork() {
    Log.i("Setting up SDK network monitoring");
    
    try {
        // Hook URL connection
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            const url = this.toString();
            
            // Check if this is an SDK-related URL
            const isSDKUrl = 
                url.includes("sdk") || 
                url.includes("api") || 
                url.includes("bearmod") || 
                url.includes("config") || 
                url.includes("update");
            
            if (isSDKUrl) {
                Log.highlight(`SDK opening connection to: ${url}`);
                
                // Track network request
                sdkState.networkRequests.push({
                    url: url,
                    type: "URL.openConnection",
                    time: new Date().getTime()
                });
            }
            
            return this.openConnection();
        };
        
        // Hook HttpURLConnection
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.connect.implementation = function() {
            const url = this.getURL().toString();
            const method = this.getRequestMethod();
            
            // Check if this is an SDK-related URL
            const isSDKUrl = 
                url.includes("sdk") || 
                url.includes("api") || 
                url.includes("bearmod") || 
                url.includes("config") || 
                url.includes("update");
            
            if (isSDKUrl) {
                Log.highlight(`SDK HTTP ${method} request to ${url}`);
                
                // Track network request
                sdkState.networkRequests.push({
                    url: url,
                    method: method,
                    type: "HttpURLConnection",
                    time: new Date().getTime()
                });
                
                // Try to get request headers
                try {
                    const headerFields = this.getRequestProperties();
                    const keys = headerFields.keySet().toArray();
                    
                    Log.i("Request headers:");
                    for (let i = 0; i < keys.length; i++) {
                        const key = keys[i];
                        const value = headerFields.get(key);
                        Log.i(`  ${key}: ${value}`);
                    }
                } catch (e) {
                    Log.d(`Could not get request headers: ${e}`);
                }
            }
            
            this.connect();
            
            if (isSDKUrl) {
                // Try to get response code and message
                try {
                    const responseCode = this.getResponseCode();
                    const responseMessage = this.getResponseMessage();
                    
                    Log.i(`Response: ${responseCode} ${responseMessage}`);
                    
                    // Update network request
                    const request = sdkState.networkRequests.find(r => 
                        r.url === url && r.type === "HttpURLConnection"
                    );
                    
                    if (request) {
                        request.responseCode = responseCode;
                        request.responseMessage = responseMessage;
                    }
                } catch (e) {
                    Log.d(`Could not get response: ${e}`);
                }
            }
        };
        
        // Hook OkHttp if available
        try {
            const OkHttpClient = Java.use("okhttp3.OkHttpClient");
            const Request = Java.use("okhttp3.Request");
            
            OkHttpClient.newCall.overload("okhttp3.Request").implementation = function(request) {
                const url = request.url().toString();
                const method = request.method();
                
                // Check if this is an SDK-related URL
                const isSDKUrl = 
                    url.includes("sdk") || 
                    url.includes("api") || 
                    url.includes("bearmod") || 
                    url.includes("config") || 
                    url.includes("update");
                
                if (isSDKUrl) {
                    Log.highlight(`SDK OkHttp ${method} request to ${url}`);
                    
                    // Track network request
                    sdkState.networkRequests.push({
                        url: url,
                        method: method,
                        type: "OkHttp",
                        time: new Date().getTime()
                    });
                    
                    // Try to get request headers
                    try {
                        const headers = request.headers();
                        const names = headers.names().toArray();
                        
                        Log.i("Request headers:");
                        for (let i = 0; i < names.length; i++) {
                            const name = names[i];
                            const value = headers.get(name);
                            Log.i(`  ${name}: ${value}`);
                        }
                    } catch (e) {
                        Log.d(`Could not get request headers: ${e}`);
                    }
                }
                
                return this.newCall(request);
            };
        } catch (e) {
            Log.d("OkHttp not found or failed to hook");
        }
        
        Log.i("SDK network monitoring set up");
    } catch (e) {
        Log.e(`Failed to set up SDK network monitoring: ${e}`);
    }
}

// Print SDK analysis report
function printSDKReport() {
    Log.highlight("SDK Analysis Report");
    
    Log.i(`SDK Initialized: ${sdkState.initialized}`);
    if (sdkState.initialized) {
        Log.i(`Initialization Time: ${sdkState.initializationTime}ms`);
    }
    
    Log.i(`Memory Usage: ${sdkState.memoryUsage} bytes`);
    
    Log.i("Function Calls:");
    Object.keys(sdkState.functionCalls).forEach(funcName => {
        const call = sdkState.functionCalls[funcName];
        Log.i(`  ${funcName}: ${call.count} calls, last called at ${new Date(call.lastCalled).toISOString()}`);
    });
    
    Log.i(`Network Requests: ${sdkState.networkRequests.length}`);
    sdkState.networkRequests.forEach((req, index) => {
        Log.i(`  ${index + 1}. ${req.method || 'GET'} ${req.url} (${req.type})`);
        if (req.responseCode) {
            Log.i(`     Response: ${req.responseCode} ${req.responseMessage || ''}`);
        }
    });
    
    Log.i(`Memory Allocations: ${sdkState.memoryAllocations.length}`);
    
    Log.highlight("End of SDK Analysis Report");
}

// Set up a timer to print the SDK report periodically
setInterval(printSDKReport, 30000); // Every 30 seconds

// Start the script
initialize();
