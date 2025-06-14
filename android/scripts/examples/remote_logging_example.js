/**
 * Bear-Mod Remote Logging Example
 * 
 * This script demonstrates how to use the remote logging features in Bear-Mod.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Remote Logging Example Loaded");

// Try to import common utilities
let common;
try {
    common = require('../utils/common.js');
} catch (e) {
    console.log("[!] Common utilities not available: " + e);
    // Define basic logging if common utilities are not available
    common = {
        Log: {
            d: function(message) { console.log(`[D] ${message}`); },
            i: function(message) { console.log(`[I] ${message}`); },
            w: function(message) { console.log(`[W] ${message}`); },
            e: function(message) { console.log(`[E] ${message}`); },
            highlight: function(message) { console.log(`\n[*] ======== ${message} ========\n`); }
        }
    };
}

// Try to import remote logging module
let RemoteLogger;
try {
    RemoteLogger = require('../utils/remote_logging.js');
    console.log("[*] Remote logging module loaded");
} catch (e) {
    console.log("[!] Remote logging module not available: " + e);
    RemoteLogger = common.Log;
}

// Try to import Web UI module
let WebUI;
try {
    WebUI = require('../utils/web_ui.js');
    console.log("[*] Web UI module loaded");
} catch (e) {
    console.log("[!] Web UI module not available: " + e);
}

// Configuration
const config = {
    // Telegram configuration
    telegram: {
        enabled: false,
        botToken: "", // Set your bot token here
        chatId: "",   // Set your chat ID here
        logLevel: "info"
    },
    
    // Discord configuration
    discord: {
        enabled: false,
        webhookUrl: "", // Set your Discord webhook URL here
        logLevel: "info"
    },
    
    // File logging configuration
    file: {
        enabled: true,
        path: "/sdcard/bear-mod-logs.txt",
        logLevel: "debug"
    },
    
    // Web UI configuration
    webUI: {
        enabled: true,
        port: 8080,
        maxLogEntries: 1000,
        enableRemoteCommands: false
    }
};

// Configure remote logging
if (RemoteLogger.configure) {
    RemoteLogger.configure({
        telegram: config.telegram,
        discord: config.discord,
        file: config.file
    });
    console.log("[*] Remote logging configured");
}

// Start Web UI server
if (WebUI && config.webUI.enabled) {
    WebUI.configure(config.webUI);
    WebUI.startServer();
    console.log("[*] Web UI server started on port " + config.webUI.port);
}

// Use the appropriate logger
const Log = WebUI && config.webUI.enabled ? WebUI.logger : RemoteLogger;

// Log some example messages
Log.highlight("Remote Logging Example Started");
Log.d("This is a debug message");
Log.i("This is an info message");
Log.w("This is a warning message");
Log.e("This is an error message");

// Log device information
Java.perform(function() {
    try {
        const Build = Java.use("android.os.Build");
        const VERSION = Java.use("android.os.Build$VERSION");
        
        Log.i("Device Information:");
        Log.i("- Manufacturer: " + Build.MANUFACTURER.value);
        Log.i("- Model: " + Build.MODEL.value);
        Log.i("- Android Version: " + VERSION.RELEASE.value + " (API " + VERSION.SDK_INT.value + ")");
        
        // Get application information
        const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        const packageName = context.getPackageName();
        const packageManager = context.getPackageManager();
        const packageInfo = packageManager.getPackageInfo(packageName, 0);
        
        Log.i("Application Information:");
        Log.i("- Package Name: " + packageName);
        Log.i("- Version: " + packageInfo.versionName.value + " (" + packageInfo.versionCode.value + ")");
    } catch (e) {
        Log.e("Error getting device information: " + e);
    }
});

// Log a message every 5 seconds
const intervalId = setInterval(function() {
    Log.i("Periodic log message: " + new Date().toISOString());
}, 5000);

// Stop logging after 1 minute
setTimeout(function() {
    clearInterval(intervalId);
    Log.highlight("Remote Logging Example Completed");
    
    // Stop Web UI server
    if (WebUI && config.webUI.enabled) {
        WebUI.stopServer();
        console.log("[*] Web UI server stopped");
    }
}, 60000);

// Cleanup function
function cleanup() {
    clearInterval(intervalId);
    
    // Stop Web UI server
    if (WebUI && config.webUI.enabled) {
        WebUI.stopServer();
        console.log("[*] Web UI server stopped");
    }
}

// Export cleanup function
module.exports = {
    cleanup: cleanup
};
