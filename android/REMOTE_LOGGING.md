# Bear-Mod Remote Logging

This document explains how to set up and use the remote logging features in Bear-Mod.

## Overview

Bear-Mod now supports sending logs to various remote destinations:

1. **Telegram** - Send logs to a Telegram bot
2. **Discord** - Send logs to a Discord webhook
3. **File** - Save logs to a file on the device
4. **Web UI** - View logs in a web browser

## Configuration

To enable remote logging, edit the `config.js` file in the root directory:

```javascript
// Remote logging configuration
remoteLogging: {
    enabled: true,  // Set to true to enable remote logging

    // Telegram configuration
    telegram: {
        enabled: true,  // Set to true to enable Telegram logging
        botToken: "YOUR_BOT_TOKEN",  // Your Telegram bot token
        chatId: "YOUR_CHAT_ID"       // Your Telegram chat ID
    },

    // Discord configuration
    discord: {
        enabled: true,  // Set to true to enable Discord logging
        webhookUrl: "YOUR_WEBHOOK_URL"  // Your Discord webhook URL
    },

    // File logging configuration
    file: {
        enabled: true,  // Set to true to enable file logging
        path: "/sdcard/bear-mod-logs.txt"  // Path to save logs
    }
}
```

## Setting Up Telegram Logging

1. **Create a Telegram Bot**:
   - Open Telegram and search for `@BotFather`
   - Send `/newbot` and follow the instructions
   - Copy the bot token (e.g., `123456789:ABCdefGhIJKlmnOPQRstUVwxYZ`)

2. **Get Your Chat ID**:
   - Send a message to your bot
   - Open `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates` in a browser
   - Look for the `chat` object and copy the `id` value

3. **Update Configuration**:
   - Set `telegram.enabled` to `true`
   - Set `telegram.botToken` to your bot token
   - Set `telegram.chatId` to your chat ID

## Setting Up Discord Logging

1. **Create a Discord Webhook**:
   - Open Discord and go to Server Settings > Integrations > Webhooks
   - Click "New Webhook" and configure it
   - Copy the webhook URL

2. **Update Configuration**:
   - Set `discord.enabled` to `true`
   - Set `discord.webhookUrl` to your webhook URL

## Log Levels

You can configure the log level for each destination:

- `debug` - All messages
- `info` - Info, warning, and error messages
- `warn` - Warning and error messages
- `error` - Only error messages

Example:

```javascript
telegram: {
    enabled: true,
    botToken: "YOUR_BOT_TOKEN",
    chatId: "YOUR_CHAT_ID",
    logLevel: "info"  // Only send info, warning, and error messages to Telegram
}
```

## Using Remote Logging in Scripts

The remote logging module is automatically loaded in the main script. You can use it like this:

```javascript
// In main.js or other scripts that load remote_logging.js
Log.d("Debug message");  // Only logged locally and to destinations with logLevel="debug"
Log.i("Info message");   // Logged to destinations with logLevel="debug" or "info"
Log.w("Warning message"); // Logged to destinations with logLevel="debug", "info", or "warn"
Log.e("Error message");  // Logged to all destinations
Log.highlight("Important message");  // Always logged to all destinations
```

## Automated Frida Server Setup

Bear-Mod now includes scripts to automatically download and set up Frida server on your device:

### Windows

```powershell
.\setup_frida.ps1
```

### Linux/macOS

```bash
chmod +x setup_frida.sh
./setup_frida.sh
```

These scripts will:
1. Detect your device's architecture
2. Download the appropriate Frida server
3. Push it to your device
4. Start the Frida server
5. Verify the connection

## Setting Up Web UI

The Web UI provides a browser-based interface for viewing logs in real-time.

1. **Enable Web UI in Configuration**:

   ```javascript
   // Web UI configuration
   webUI: {
       enabled: true,
       port: 8080,
       logLevel: "debug"
   }
   ```

2. **Start the Web UI Server**:

   The Web UI server will start automatically when you run the main script with Web UI enabled.

3. **Access the Web UI**:

   Open your browser and navigate to `http://localhost:8080`

   If you're accessing from another device, replace `localhost` with the IP address of your device.

4. **Port Forwarding (if needed)**:

   If you're accessing from another device, you may need to set up port forwarding:

   ```bash
   adb forward tcp:8080 tcp:8080
   ```

### Web UI Features

- **Real-time Log Viewing**: Logs are updated in real-time as they are generated
- **Filtering**: Filter logs by level (debug, info, warning, error) or by text
- **Clearing Logs**: Clear all logs with a single click
- **Remote Commands**: Execute JavaScript commands remotely (disabled by default for security)

## Troubleshooting

### Telegram Logs Not Sending

- Make sure your bot token and chat ID are correct
- Check that you've started a conversation with your bot
- Verify that your device has internet access

### Discord Logs Not Sending

- Make sure your webhook URL is correct
- Verify that your device has internet access

### File Logs Not Writing

- Make sure the directory exists and is writable
- Check that your app has storage permissions

### Web UI Not Working

- Make sure the port is not in use by another application
- Check that port forwarding is set up correctly if accessing from another device
- Verify that your device has the necessary permissions to create a server socket
