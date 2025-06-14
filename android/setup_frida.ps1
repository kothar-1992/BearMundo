# Automated Frida Server Deployment Script for Windows
# This script automatically detects device architecture, downloads and deploys Frida server

# Print banner
Write-Host "╔═══════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║         Bear-Mod Frida Server Setup       ║" -ForegroundColor Blue
Write-Host "╚═══════════════════════════════════════════╝" -ForegroundColor Blue

# Check if ADB is installed
try {
    $adbVersion = adb version
} catch {
    Write-Host "[ERROR] ADB is not installed or not in PATH. Please install Android SDK platform tools." -ForegroundColor Red
    exit 1
}

# Check if device is connected
Write-Host "[*] Checking for connected devices..." -ForegroundColor Yellow
$devices = adb devices
if (-not ($devices -match "device$")) {
    Write-Host "[ERROR] No device connected. Please connect a device and try again." -ForegroundColor Red
    exit 1
}

# Get device architecture
Write-Host "[*] Detecting device architecture..." -ForegroundColor Yellow
$deviceArch = adb shell getprop ro.product.cpu.abi
Write-Host "[+] Detected architecture: $deviceArch" -ForegroundColor Green

# Set Frida version - can be updated as needed
$fridaVersion = "16.1.3"
Write-Host "[*] Using Frida version: $fridaVersion" -ForegroundColor Yellow

# Map Android architecture to Frida architecture
switch -Regex ($deviceArch) {
    "armeabi-v7a" { $fridaArch = "arm" }
    "arm64-v8a" { $fridaArch = "arm64" }
    "x86" { $fridaArch = "x86" }
    "x86_64" { $fridaArch = "x86_64" }
    default {
        Write-Host "[ERROR] Unsupported architecture: $deviceArch" -ForegroundColor Red
        exit 1
    }
}

# Set Frida server filename
$fridaServer = "frida-server-$fridaVersion-android-$fridaArch"
$fridaServerXz = "$fridaServer.xz"
$fridaUrl = "https://github.com/frida/frida/releases/download/$fridaVersion/$fridaServerXz"

# Create a directory for Frida server if it doesn't exist
$fridaServerDir = Join-Path $PSScriptRoot "frida-server"
if (-not (Test-Path $fridaServerDir)) {
    New-Item -Path $fridaServerDir -ItemType Directory | Out-Null
}

# Download Frida server if it doesn't exist
$fridaServerPath = Join-Path $fridaServerDir $fridaServer
if (-not (Test-Path $fridaServerPath)) {
    Write-Host "[*] Downloading Frida server..." -ForegroundColor Yellow
    Write-Host "[*] URL: $fridaUrl" -ForegroundColor Blue
    
    $fridaServerXzPath = Join-Path $fridaServerDir $fridaServerXz
    
    try {
        # Use .NET WebClient to download the file
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($fridaUrl, $fridaServerXzPath)
    } catch {
        Write-Host "[ERROR] Failed to download Frida server: $_" -ForegroundColor Red
        exit 1
    }
    
    # Extract Frida server
    Write-Host "[*] Extracting Frida server..." -ForegroundColor Yellow
    
    # Check if 7-Zip is installed
    $7zipPath = "C:\Program Files\7-Zip\7z.exe"
    if (Test-Path $7zipPath) {
        & $7zipPath e $fridaServerXzPath -o"$fridaServerDir" -y | Out-Null
    } else {
        Write-Host "[ERROR] 7-Zip is not installed. Please install 7-Zip or extract the .xz file manually." -ForegroundColor Red
        Write-Host "Download URL: $fridaUrl" -ForegroundColor Yellow
        exit 1
    }
    
    # Remove the .xz file
    Remove-Item $fridaServerXzPath
} else {
    Write-Host "[+] Frida server already exists. Skipping download." -ForegroundColor Green
}

# Kill any running Frida server
Write-Host "[*] Killing any running Frida server..." -ForegroundColor Yellow
adb shell "pkill frida-server" 2>$null

# Push Frida server to device
Write-Host "[*] Pushing Frida server to device..." -ForegroundColor Yellow
adb push $fridaServerPath /data/local/tmp/frida-server

# Set executable permissions
Write-Host "[*] Setting executable permissions..." -ForegroundColor Yellow
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start Frida server
Write-Host "[*] Starting Frida server..." -ForegroundColor Yellow
# Try with root first, then without if it fails
adb shell "su -c '/data/local/tmp/frida-server &'" 2>$null
if ($LASTEXITCODE -ne 0) {
    adb shell "/data/local/tmp/frida-server &"
}

# Forward port
Write-Host "[*] Forwarding port..." -ForegroundColor Yellow
adb forward tcp:27042 tcp:27042

# Wait for Frida server to start
Write-Host "[*] Waiting for Frida server to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

# Verify connection
Write-Host "[*] Verifying connection..." -ForegroundColor Yellow
try {
    frida-ps -U | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Frida server is running successfully!" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Failed to connect to Frida server." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "[*] frida-ps not found. Please install Frida tools:" -ForegroundColor Yellow
    Write-Host "    pip install frida-tools" -ForegroundColor Blue
}

Write-Host "[+] Setup complete!" -ForegroundColor Green
