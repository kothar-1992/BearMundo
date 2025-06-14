/**
 * Bear-Mod Main Script
 *
 * This script provides a unified interface to load all Bear-Mod modules.
 *
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Bear-Mod Main Script Loaded");

// Load configuration
let config;
try {
    // Try to load external configuration
    config = require('../config.js');
    console.log("[*] Loaded external configuration");
} catch (e) {
    console.log("[!] External configuration not found, using default configuration");

    // Default configuration
    config = {
        enableStealth: true,
        bypassSignature: true,
        bypassSSLPinning: true,
        bypassRootDetection: true,
        analyzeApp: true,
        logLevel: "info", // debug, info, warn, error

        // Remote logging configuration
        remoteLogging: {
            enabled: false,
            telegram: {
                enabled: false,
                botToken: "", // Set your bot token here
                chatId: ""    // Set your chat ID here
            },
            discord: {
                enabled: false,
                webhookUrl: "" // Set your Discord webhook URL here
            },
            file: {
                enabled: true,
                path: "/sdcard/bear-mod-logs.txt"
            }
        }
    };
}

// Setup logging
let Log;

// Try to load remote logging module
try {
    const RemoteLogger = require('./utils/remote_logging.js');

    // Configure remote logging if enabled
    if (config.remoteLogging.enabled) {
        RemoteLogger.configure({
            telegram: config.remoteLogging.telegram,
            discord: config.remoteLogging.discord,
            file: config.remoteLogging.file
        });
        console.log("[*] Remote logging enabled");
    }

    // Use remote logger
    Log = RemoteLogger;
} catch (e) {
    console.log("[!] Remote logging module not available: " + e);
}

// Try to load Web UI module
try {
    if (config.remoteLogging?.webUI?.enabled) {
        const WebUI = require('./utils/web_ui.js');

        // Configure Web UI
        WebUI.configure(config.remoteLogging.webUI);

        // Start Web UI server
        WebUI.startServer();

        // Use Web UI logger if remote logging is not enabled
        if (!config.remoteLogging.enabled) {
            Log = WebUI.logger;
        }

        console.log("[*] Web UI enabled on port " + (config.remoteLogging.webUI.port || 8080));
    }
} catch (e) {
    console.log("[!] Web UI module not available: " + e);

    // Fallback to basic logging
    Log = {
        d: function(message) {
            if (config.logLevel === "debug") {
                console.log(`[D] ${message}`);
            }
        },
        i: function(message) {
            if (config.logLevel === "debug" || config.logLevel === "info") {
                console.log(`[I] ${message}`);
            }
        },
        w: function(message) {
            if (config.logLevel === "debug" || config.logLevel === "info" || config.logLevel === "warn") {
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
}

// Load modules based on configuration
function loadModules() {
    Log.highlight("Loading Bear-Mod Modules");

    // Enable stealth mode
    if (config.enableStealth) {
        try {
            const antiDetection = require('./stealth/anti_detection.js');
            antiDetection.setupAntiDetection();
            Log.i("Anti-detection module loaded");
        } catch (e) {
            Log.e("Failed to load anti-detection module: " + e);
        }
    }

    // Load modules in Java context
    Java.perform(function() {
        // Bypass signature verification
        if (config.bypassSignature) {
            try {
                Log.i("Loading signature bypass module");
                require('./bypass/signature_bypass.js');
                Log.i("Signature bypass module loaded");
            } catch (e) {
                Log.e("Failed to load signature bypass module: " + e);
            }
        }

        // Bypass SSL pinning
        if (config.bypassSSLPinning) {
            try {
                Log.i("Loading SSL pinning bypass module");
                require('./bypass/ssl_bypass.js');
                Log.i("SSL pinning bypass module loaded");
            } catch (e) {
                Log.e("Failed to load SSL pinning bypass module: " + e);
            }
        }

        // Bypass root detection
        if (config.bypassRootDetection) {
            try {
                Log.i("Loading root detection bypass module");
                require('./bypass/root_bypass.js');
                Log.i("Root detection bypass module loaded");
            } catch (e) {
                Log.e("Failed to load root detection bypass module: " + e);
            }
        }

        // Analyze app
        if (config.analyzeApp) {
            try {
                Log.i("Loading app analyzer module");
                require('./analysis/app_analyzer.js');
                Log.i("App analyzer module loaded");
            } catch (e) {
                Log.e("Failed to load app analyzer module: " + e);
            }
        }
    });

    Log.highlight("All modules loaded");
}

// Initialize
loadModules();

console.log("[*] Bear-Mod initialization complete");
