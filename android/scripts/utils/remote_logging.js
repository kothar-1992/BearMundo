/**
 * Bear-Mod Remote Logging Module
 * 
 * This script provides functionality to send logs to remote services like
 * Telegram, Discord, or a local web UI.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Remote Logging Module Loaded");

// Try to import common utilities
let common;
try {
    common = require('./common.js');
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

const Log = common.Log;

// Configuration
const config = {
    // Telegram configuration
    telegram: {
        enabled: false,
        botToken: "", // Set your bot token here
        chatId: "",   // Set your chat ID here
        logLevel: "info", // debug, info, warn, error
    },
    
    // Discord configuration
    discord: {
        enabled: false,
        webhookUrl: "", // Set your Discord webhook URL here
        logLevel: "info", // debug, info, warn, error
    },
    
    // Local web UI configuration
    webUI: {
        enabled: false,
        port: 8080,
        logLevel: "debug", // debug, info, warn, error
    },
    
    // File logging configuration
    file: {
        enabled: true,
        path: "/sdcard/bear-mod-logs.txt",
        logLevel: "debug", // debug, info, warn, error
    }
};

// Log levels
const LOG_LEVELS = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3
};

// Check if log should be sent based on log level
function shouldSendLog(configLogLevel, messageLogLevel) {
    return LOG_LEVELS[messageLogLevel] >= LOG_LEVELS[configLogLevel];
}

// Format log message
function formatLogMessage(level, message) {
    const timestamp = new Date().toISOString();
    let appInfo = "";
    
    // Try to get app information
    try {
        Java.perform(function() {
            const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            const packageName = context.getPackageName();
            appInfo = `[${packageName}] `;
        });
    } catch (e) {
        // Ignore errors
    }
    
    return `${timestamp} [${level.toUpperCase()}] ${appInfo}${message}`;
}

// Send log to Telegram
function sendToTelegram(level, message) {
    if (!config.telegram.enabled || !shouldSendLog(config.telegram.logLevel, level)) {
        return;
    }
    
    const formattedMessage = formatLogMessage(level, message);
    const botToken = config.telegram.botToken;
    const chatId = config.telegram.chatId;
    
    if (!botToken || !chatId) {
        Log.e("Telegram bot token or chat ID not configured");
        return;
    }
    
    const url = `https://api.telegram.org/bot${botToken}/sendMessage?chat_id=${chatId}&text=${encodeURIComponent(formattedMessage)}`;
    
    Java.perform(function() {
        try {
            Java.use("java.net.URL").$new(url).openStream().close();
            Log.d(`Sent log to Telegram: ${level} - ${message}`);
        } catch (e) {
            Log.e(`Failed to send log to Telegram: ${e}`);
        }
    });
}

// Send log to Discord
function sendToDiscord(level, message) {
    if (!config.discord.enabled || !shouldSendLog(config.discord.logLevel, level)) {
        return;
    }
    
    const formattedMessage = formatLogMessage(level, message);
    const webhookUrl = config.discord.webhookUrl;
    
    if (!webhookUrl) {
        Log.e("Discord webhook URL not configured");
        return;
    }
    
    // Create JSON payload
    const payload = JSON.stringify({
        content: formattedMessage
    });
    
    Java.perform(function() {
        try {
            const URL = Java.use("java.net.URL");
            const HttpURLConnection = Java.use("java.net.HttpURLConnection");
            const OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
            const BufferedReader = Java.use("java.io.BufferedReader");
            const InputStreamReader = Java.use("java.io.InputStreamReader");
            
            const url = URL.$new(webhookUrl);
            const connection = Java.cast(url.openConnection(), HttpURLConnection);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);
            
            const writer = OutputStreamWriter.$new(connection.getOutputStream());
            writer.write(payload);
            writer.flush();
            
            const responseCode = connection.getResponseCode();
            if (responseCode === 204) {
                Log.d(`Sent log to Discord: ${level} - ${message}`);
            } else {
                Log.e(`Failed to send log to Discord: HTTP ${responseCode}`);
            }
            
            writer.close();
        } catch (e) {
            Log.e(`Failed to send log to Discord: ${e}`);
        }
    });
}

// Send log to local file
function sendToFile(level, message) {
    if (!config.file.enabled || !shouldSendLog(config.file.logLevel, level)) {
        return;
    }
    
    const formattedMessage = formatLogMessage(level, message);
    const path = config.file.path;
    
    Java.perform(function() {
        try {
            const File = Java.use("java.io.File");
            const FileWriter = Java.use("java.io.FileWriter");
            const BufferedWriter = Java.use("java.io.BufferedWriter");
            
            const file = File.$new(path);
            const writer = BufferedWriter.$new(FileWriter.$new(file, true));
            
            writer.write(formattedMessage + "\n");
            writer.flush();
            writer.close();
            
            Log.d(`Wrote log to file: ${level} - ${message}`);
        } catch (e) {
            Log.e(`Failed to write log to file: ${e}`);
        }
    });
}

// Send log to all configured destinations
function sendLog(level, message) {
    sendToTelegram(level, message);
    sendToDiscord(level, message);
    sendToFile(level, message);
}

// Create enhanced logger
const RemoteLogger = {
    // Configure remote logging
    configure: function(newConfig) {
        if (newConfig.telegram) {
            config.telegram = { ...config.telegram, ...newConfig.telegram };
        }
        if (newConfig.discord) {
            config.discord = { ...config.discord, ...newConfig.discord };
        }
        if (newConfig.webUI) {
            config.webUI = { ...config.webUI, ...newConfig.webUI };
        }
        if (newConfig.file) {
            config.file = { ...config.file, ...newConfig.file };
        }
        
        Log.i("Remote logging configuration updated");
    },
    
    // Debug log
    d: function(message) {
        Log.d(message);
        sendLog("debug", message);
    },
    
    // Info log
    i: function(message) {
        Log.i(message);
        sendLog("info", message);
    },
    
    // Warning log
    w: function(message) {
        Log.w(message);
        sendLog("warn", message);
    },
    
    // Error log
    e: function(message) {
        Log.e(message);
        sendLog("error", message);
    },
    
    // Highlight log (always sent)
    highlight: function(message) {
        Log.highlight(message);
        sendLog("info", `=== ${message} ===`);
    },
    
    // Send a screenshot to remote destinations
    sendScreenshot: function() {
        Java.perform(function() {
            try {
                // This is a simplified version - a real implementation would need to capture the screen
                // and send the image to remote destinations
                Log.i("Screenshot functionality not implemented yet");
            } catch (e) {
                Log.e(`Failed to capture screenshot: ${e}`);
            }
        });
    }
};

// Export the remote logger
module.exports = RemoteLogger;
