/**
 * Bear-Mod Web UI
 * 
 * This script provides a simple web UI for viewing logs and interacting with Bear-Mod.
 * 
 * DISCLAIMER:
 * Bear-Mod is designed for security researchers, app developers, and educational purposes only.
 * Users must:
 * 1. Only analyze applications they own or have explicit permission to test
 * 2. Respect intellectual property rights and terms of service
 * 3. Use findings responsibly through proper disclosure channels
 * 4. Not use this tool to access unauthorized content or services
 */

console.log("[*] Web UI Module Loaded");

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
    port: 8080,
    maxLogEntries: 1000,
    enableRemoteCommands: false
};

// Log storage
const logs = [];
let server = null;
let isRunning = false;

// HTML template for the web UI
const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bear-Mod Web UI</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #1e1e1e;
            color: #e0e0e0;
        }
        header {
            background-color: #2d2d2d;
            padding: 1rem;
            border-bottom: 1px solid #3e3e3e;
        }
        h1 {
            margin: 0;
            font-size: 1.5rem;
        }
        .container {
            display: flex;
            height: calc(100vh - 60px);
        }
        .sidebar {
            width: 200px;
            background-color: #252525;
            padding: 1rem;
            border-right: 1px solid #3e3e3e;
            overflow-y: auto;
        }
        .main {
            flex: 1;
            padding: 1rem;
            overflow-y: auto;
        }
        .log-entry {
            margin-bottom: 0.5rem;
            padding: 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .log-debug {
            background-color: #2d2d2d;
            color: #a0a0a0;
        }
        .log-info {
            background-color: #2d2d2d;
            color: #6a9eff;
        }
        .log-warn {
            background-color: #3d3d00;
            color: #ffff00;
        }
        .log-error {
            background-color: #3d0000;
            color: #ff6a6a;
        }
        .log-highlight {
            background-color: #003d3d;
            color: #6affff;
            font-weight: bold;
        }
        .log-timestamp {
            color: #a0a0a0;
            font-size: 0.8rem;
        }
        .filter-group {
            margin-bottom: 1rem;
        }
        .filter-group h3 {
            margin-top: 0;
            margin-bottom: 0.5rem;
        }
        .filter-option {
            margin-bottom: 0.25rem;
        }
        .command-input {
            display: flex;
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid #3e3e3e;
        }
        .command-input input {
            flex: 1;
            padding: 0.5rem;
            background-color: #2d2d2d;
            border: 1px solid #3e3e3e;
            color: #e0e0e0;
            border-radius: 4px 0 0 4px;
        }
        .command-input button {
            padding: 0.5rem 1rem;
            background-color: #0078d4;
            border: none;
            color: white;
            border-radius: 0 4px 4px 0;
            cursor: pointer;
        }
        .command-input button:hover {
            background-color: #0066b3;
        }
        .status {
            margin-top: 1rem;
            font-size: 0.9rem;
            color: #a0a0a0;
        }
        .clear-logs {
            margin-top: 1rem;
            padding: 0.5rem;
            background-color: #3d3d3d;
            border: none;
            color: white;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
        }
        .clear-logs:hover {
            background-color: #4d4d4d;
        }
    </style>
</head>
<body>
    <header>
        <h1>Bear-Mod Web UI</h1>
    </header>
    <div class="container">
        <div class="sidebar">
            <div class="filter-group">
                <h3>Log Levels</h3>
                <div class="filter-option">
                    <input type="checkbox" id="filter-debug" checked>
                    <label for="filter-debug">Debug</label>
                </div>
                <div class="filter-option">
                    <input type="checkbox" id="filter-info" checked>
                    <label for="filter-info">Info</label>
                </div>
                <div class="filter-option">
                    <input type="checkbox" id="filter-warn" checked>
                    <label for="filter-warn">Warning</label>
                </div>
                <div class="filter-option">
                    <input type="checkbox" id="filter-error" checked>
                    <label for="filter-error">Error</label>
                </div>
                <div class="filter-option">
                    <input type="checkbox" id="filter-highlight" checked>
                    <label for="filter-highlight">Highlight</label>
                </div>
            </div>
            <div class="filter-group">
                <h3>Search</h3>
                <input type="text" id="search" placeholder="Filter logs...">
            </div>
            <button class="clear-logs" id="clear-logs">Clear Logs</button>
            <div class="status">
                <p>Connected to: <span id="app-name">Unknown</span></p>
                <p>Log entries: <span id="log-count">0</span></p>
            </div>
        </div>
        <div class="main">
            <div id="logs"></div>
            <div class="command-input" id="command-container" style="display: none;">
                <input type="text" id="command" placeholder="Enter command...">
                <button id="send-command">Send</button>
            </div>
        </div>
    </div>
    <script>
        // Log filtering
        function applyFilters() {
            const debugEnabled = document.getElementById('filter-debug').checked;
            const infoEnabled = document.getElementById('filter-info').checked;
            const warnEnabled = document.getElementById('filter-warn').checked;
            const errorEnabled = document.getElementById('filter-error').checked;
            const highlightEnabled = document.getElementById('filter-highlight').checked;
            const searchText = document.getElementById('search').value.toLowerCase();
            
            const logEntries = document.querySelectorAll('.log-entry');
            let visibleCount = 0;
            
            logEntries.forEach(entry => {
                const isDebug = entry.classList.contains('log-debug');
                const isInfo = entry.classList.contains('log-info');
                const isWarn = entry.classList.contains('log-warn');
                const isError = entry.classList.contains('log-error');
                const isHighlight = entry.classList.contains('log-highlight');
                const text = entry.textContent.toLowerCase();
                
                const levelMatch = (isDebug && debugEnabled) ||
                                  (isInfo && infoEnabled) ||
                                  (isWarn && warnEnabled) ||
                                  (isError && errorEnabled) ||
                                  (isHighlight && highlightEnabled);
                                  
                const searchMatch = searchText === '' || text.includes(searchText);
                
                if (levelMatch && searchMatch) {
                    entry.style.display = '';
                    visibleCount++;
                } else {
                    entry.style.display = 'none';
                }
            });
            
            document.getElementById('log-count').textContent = visibleCount;
        }
        
        // Event listeners
        document.getElementById('filter-debug').addEventListener('change', applyFilters);
        document.getElementById('filter-info').addEventListener('change', applyFilters);
        document.getElementById('filter-warn').addEventListener('change', applyFilters);
        document.getElementById('filter-error').addEventListener('change', applyFilters);
        document.getElementById('filter-highlight').addEventListener('change', applyFilters);
        document.getElementById('search').addEventListener('input', applyFilters);
        
        // Clear logs
        document.getElementById('clear-logs').addEventListener('click', () => {
            document.getElementById('logs').innerHTML = '';
            document.getElementById('log-count').textContent = '0';
            fetch('/clear-logs');
        });
        
        // Command input
        const commandEnabled = ${config.enableRemoteCommands};
        if (commandEnabled) {
            document.getElementById('command-container').style.display = 'flex';
            document.getElementById('send-command').addEventListener('click', () => {
                const command = document.getElementById('command').value;
                if (command) {
                    fetch('/command', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ command })
                    });
                    document.getElementById('command').value = '';
                }
            });
            
            document.getElementById('command').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    document.getElementById('send-command').click();
                }
            });
        }
        
        // Auto-refresh logs
        function fetchLogs() {
            fetch('/logs')
                .then(response => response.json())
                .then(data => {
                    const logsContainer = document.getElementById('logs');
                    logsContainer.innerHTML = '';
                    
                    data.logs.forEach(log => {
                        const logEntry = document.createElement('div');
                        logEntry.className = \`log-entry log-\${log.level}\`;
                        
                        const timestamp = document.createElement('span');
                        timestamp.className = 'log-timestamp';
                        timestamp.textContent = log.timestamp + ' ';
                        
                        logEntry.appendChild(timestamp);
                        logEntry.appendChild(document.createTextNode(log.message));
                        
                        logsContainer.appendChild(logEntry);
                    });
                    
                    document.getElementById('app-name').textContent = data.appName || 'Unknown';
                    document.getElementById('log-count').textContent = data.logs.length;
                    
                    applyFilters();
                })
                .catch(error => console.error('Error fetching logs:', error));
        }
        
        // Initial fetch and auto-refresh
        fetchLogs();
        setInterval(fetchLogs, 1000);
    </script>
</body>
</html>
`;

// Add a log entry
function addLog(level, message) {
    const timestamp = new Date().toISOString();
    logs.push({
        timestamp,
        level,
        message
    });
    
    // Limit the number of log entries
    if (logs.length > config.maxLogEntries) {
        logs.shift();
    }
}

// Start the web server
function startServer() {
    if (isRunning) {
        Log.w("Web UI server is already running");
        return;
    }
    
    try {
        Java.perform(function() {
            const ServerSocket = Java.use("java.net.ServerSocket");
            const Socket = Java.use("java.net.Socket");
            const PrintWriter = Java.use("java.io.PrintWriter");
            const BufferedReader = Java.use("java.io.BufferedReader");
            const InputStreamReader = Java.use("java.io.InputStreamReader");
            const Thread = Java.use("java.lang.Thread");
            const Runnable = Java.use("java.lang.Runnable");
            
            // Get application name
            let appName = "Unknown";
            try {
                const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
                appName = context.getPackageName();
            } catch (e) {
                Log.e("Failed to get application name: " + e);
            }
            
            // Create a server socket
            server = ServerSocket.$new(config.port);
            isRunning = true;
            
            Log.highlight(`Web UI server started on http://localhost:${config.port}`);
            Log.i("Open this URL in your browser to view logs");
            
            // Create a thread to handle connections
            const ConnectionHandler = Java.registerClass({
                name: "com.bearmod.WebUIConnectionHandler",
                implements: [Runnable],
                methods: {
                    run: function() {
                        while (isRunning) {
                            try {
                                const socket = server.accept();
                                const clientHandler = ClientHandler.$new(socket, appName);
                                const clientThread = Thread.$new(clientHandler);
                                clientThread.start();
                            } catch (e) {
                                if (isRunning) {
                                    Log.e("Error accepting connection: " + e);
                                }
                            }
                        }
                    }
                }
            });
            
            // Create a class to handle client connections
            const ClientHandler = Java.registerClass({
                name: "com.bearmod.WebUIClientHandler",
                implements: [Runnable],
                fields: {
                    socket: "java.net.Socket",
                    appName: "java.lang.String"
                },
                methods: {
                    $init: function(socket, appName) {
                        this.socket = socket;
                        this.appName = appName;
                    },
                    run: function() {
                        try {
                            const reader = BufferedReader.$new(InputStreamReader.$new(this.socket.getInputStream()));
                            const writer = PrintWriter.$new(this.socket.getOutputStream(), true);
                            
                            // Read the request line
                            const requestLine = reader.readLine();
                            if (!requestLine) {
                                return;
                            }
                            
                            // Parse the request
                            const parts = requestLine.split(" ");
                            const method = parts[0];
                            const path = parts[1];
                            
                            // Skip headers
                            let line;
                            let contentLength = 0;
                            while ((line = reader.readLine()) != null && line.length > 0) {
                                if (line.startsWith("Content-Length:")) {
                                    contentLength = parseInt(line.substring(15).trim());
                                }
                            }
                            
                            // Read request body if present
                            let body = "";
                            if (contentLength > 0) {
                                const buffer = Java.array('char', contentLength);
                                reader.read(buffer, 0, contentLength);
                                body = Java.use("java.lang.String").$new(buffer).toString();
                            }
                            
                            // Handle the request
                            if (path === "/") {
                                // Serve the main page
                                writer.println("HTTP/1.1 200 OK");
                                writer.println("Content-Type: text/html");
                                writer.println("");
                                writer.println(htmlTemplate);
                            } else if (path === "/logs") {
                                // Serve logs as JSON
                                const response = JSON.stringify({
                                    appName: this.appName,
                                    logs: logs
                                });
                                
                                writer.println("HTTP/1.1 200 OK");
                                writer.println("Content-Type: application/json");
                                writer.println("");
                                writer.println(response);
                            } else if (path === "/clear-logs" && method === "GET") {
                                // Clear logs
                                logs.length = 0;
                                
                                writer.println("HTTP/1.1 200 OK");
                                writer.println("Content-Type: text/plain");
                                writer.println("");
                                writer.println("Logs cleared");
                            } else if (path === "/command" && method === "POST" && config.enableRemoteCommands) {
                                // Execute command
                                try {
                                    const command = JSON.parse(body).command;
                                    Log.i(`Executing command: ${command}`);
                                    
                                    // Execute the command (this is potentially dangerous)
                                    const result = eval(command);
                                    
                                    writer.println("HTTP/1.1 200 OK");
                                    writer.println("Content-Type: text/plain");
                                    writer.println("");
                                    writer.println(result);
                                } catch (e) {
                                    writer.println("HTTP/1.1 500 Internal Server Error");
                                    writer.println("Content-Type: text/plain");
                                    writer.println("");
                                    writer.println("Error: " + e);
                                }
                            } else {
                                // Not found
                                writer.println("HTTP/1.1 404 Not Found");
                                writer.println("Content-Type: text/plain");
                                writer.println("");
                                writer.println("Not found");
                            }
                            
                            // Close the connection
                            writer.close();
                            reader.close();
                            this.socket.close();
                        } catch (e) {
                            Log.e("Error handling client: " + e);
                        }
                    }
                }
            });
            
            // Start the server thread
            const serverThread = Thread.$new(ConnectionHandler.$new());
            serverThread.start();
        });
    } catch (e) {
        Log.e("Failed to start Web UI server: " + e);
        isRunning = false;
    }
}

// Stop the web server
function stopServer() {
    if (!isRunning) {
        Log.w("Web UI server is not running");
        return;
    }
    
    try {
        Java.perform(function() {
            if (server) {
                server.close();
                server = null;
            }
            isRunning = false;
            Log.i("Web UI server stopped");
        });
    } catch (e) {
        Log.e("Failed to stop Web UI server: " + e);
    }
}

// Create a custom logger that adds logs to the web UI
const WebUILogger = {
    d: function(message) {
        Log.d(message);
        addLog("debug", message);
    },
    
    i: function(message) {
        Log.i(message);
        addLog("info", message);
    },
    
    w: function(message) {
        Log.w(message);
        addLog("warn", message);
    },
    
    e: function(message) {
        Log.e(message);
        addLog("error", message);
    },
    
    highlight: function(message) {
        Log.highlight(message);
        addLog("highlight", message);
    }
};

// Configure the web UI
function configure(newConfig) {
    if (newConfig.port) {
        config.port = newConfig.port;
    }
    
    if (newConfig.maxLogEntries) {
        config.maxLogEntries = newConfig.maxLogEntries;
    }
    
    if (newConfig.enableRemoteCommands !== undefined) {
        config.enableRemoteCommands = newConfig.enableRemoteCommands;
    }
    
    Log.i("Web UI configuration updated");
}

// Export the web UI module
module.exports = {
    startServer: startServer,
    stopServer: stopServer,
    configure: configure,
    logger: WebUILogger
};
