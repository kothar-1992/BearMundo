# Bear-Mod Frida Launcher
# This script helps set up and run Frida with Bear-Mod scripts

param (
    [string]$packageName = "",
    [string]$script = "main.js",
    [switch]$setup,
    [switch]$list,
    [switch]$help
)

# Display help
if ($help) {
    Write-Host "Bear-Mod Frida Launcher" -ForegroundColor Green
    Write-Host "Usage: .\run-frida.ps1 [options]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -packageName <name>  Target package name (e.g., com.example.app)" -ForegroundColor White
    Write-Host "  -script <path>        Script to run (default: main.js)" -ForegroundColor White
    Write-Host "  -setup                Set up Frida server on device" -ForegroundColor White
    Write-Host "  -list                 List running processes on device" -ForegroundColor White
    Write-Host "  -help                 Display this help message" -ForegroundColor White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\run-frida.ps1 -setup" -ForegroundColor White
    Write-Host "  .\run-frida.ps1 -list" -ForegroundColor White
    Write-Host "  .\run-frida.ps1 -packageName com.example.app -script scripts/bypass/signature_bypass.js" -ForegroundColor White
    exit 0
}

# Set up Frida server
if ($setup) {
    Write-Host "Setting up Frida server on device..." -ForegroundColor Green
    
    # Check if device is connected
    $devices = adb devices
    if (-not ($devices -match "device$")) {
        Write-Host "No device connected. Please connect a device and try again." -ForegroundColor Red
        exit 1
    }
    
    # Check if frida-server exists in frida-server directory
    $fridaServerPath = Join-Path $PSScriptRoot "frida-server"
    $fridaServerFiles = Get-ChildItem -Path $fridaServerPath -Filter "frida-server-*" -ErrorAction SilentlyContinue
    
    if ($fridaServerFiles.Count -eq 0) {
        Write-Host "No Frida server found in frida-server directory." -ForegroundColor Red
        Write-Host "Please download the appropriate Frida server for your device from:" -ForegroundColor Yellow
        Write-Host "https://github.com/frida/frida/releases" -ForegroundColor Yellow
        Write-Host "and place it in the frida-server directory." -ForegroundColor Yellow
        exit 1
    }
    
    # Use the latest Frida server
    $fridaServer = $fridaServerFiles | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
    $fridaServerName = $fridaServer.Name
    
    Write-Host "Using Frida server: $fridaServerName" -ForegroundColor Green
    
    # Kill any running Frida server
    Write-Host "Killing any running Frida server..." -ForegroundColor Yellow
    adb shell "pkill frida-server" 2>$null
    
    # Push Frida server to device
    Write-Host "Pushing Frida server to device..." -ForegroundColor Yellow
    adb push "$fridaServerPath\$fridaServerName" /data/local/tmp/frida-server
    
    # Set executable permissions
    Write-Host "Setting executable permissions..." -ForegroundColor Yellow
    adb shell "chmod 755 /data/local/tmp/frida-server"
    
    # Start Frida server
    Write-Host "Starting Frida server..." -ForegroundColor Yellow
    adb shell "/data/local/tmp/frida-server &"
    
    # Forward port
    Write-Host "Forwarding port..." -ForegroundColor Yellow
    adb forward tcp:27042 tcp:27042
    
    # Verify connection
    Write-Host "Verifying connection..." -ForegroundColor Yellow
    frida-ps -U
    
    Write-Host "Frida setup complete!" -ForegroundColor Green
    exit 0
}

# List processes
if ($list) {
    Write-Host "Listing processes on device..." -ForegroundColor Green
    frida-ps -U
    exit 0
}

# Run script
if ($packageName -eq "") {
    Write-Host "Please specify a package name with -packageName" -ForegroundColor Red
    Write-Host "Use -help for usage information" -ForegroundColor Yellow
    exit 1
}

# Check if script exists
$scriptPath = Join-Path $PSScriptRoot $script
if (-not (Test-Path $scriptPath)) {
    Write-Host "Script not found: $scriptPath" -ForegroundColor Red
    exit 1
}

# Run Frida with script
Write-Host "Running Frida with script: $scriptPath" -ForegroundColor Green
Write-Host "Target package: $packageName" -ForegroundColor Green
frida -U -n $packageName -l $scriptPath --no-pause

Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
