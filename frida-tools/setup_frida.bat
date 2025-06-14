@echo off
setlocal enabledelayedexpansion

echo ===== BearMod Frida Setup =====
echo.

:: Check if Python is installed
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed. Please install Python and try again.
    goto :end
)

:: Install Frida tools on PC
echo [INFO] Installing Frida tools on PC...
pip install frida-tools frida

:: Verify installation
where frida >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Frida installation failed. Please check your Python setup and try again.
    goto :end
)

for /f "tokens=*" %%a in ('frida --version') do set FRIDA_VERSION=%%a
echo [SUCCESS] Frida tools installed successfully: %FRIDA_VERSION%

:: Check if ADB is available
where adb >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] ADB is not available. Please install Android SDK platform tools and try again.
    goto :end
)

:: Check if device is connected
echo [INFO] Checking for connected Android devices...
for /f "tokens=*" %%a in ('adb devices ^| findstr "device$" ^| find /c /v ""') do set DEVICES=%%a

if %DEVICES% EQU 0 (
    echo [ERROR] No Android devices connected. Please connect a device and enable USB debugging.
    goto :end
)

echo [SUCCESS] Found %DEVICES% connected device(s)

:: Determine device architecture
echo [INFO] Determining device architecture...
for /f "tokens=*" %%a in ('adb shell getprop ro.product.cpu.abi') do set ARCH=%%a
echo [INFO] Device architecture: %ARCH%

:: Set Frida server version
set FRIDA_VERSION=16.1.1

:: Download appropriate Frida server
echo [INFO] Downloading Frida server for %ARCH%...

if "%ARCH%"=="arm64-v8a" (
    set FRIDA_SERVER_URL=https://github.com/frida/frida/releases/download/%FRIDA_VERSION%/frida-server-%FRIDA_VERSION%-android-arm64.xz
    set FRIDA_SERVER_FILE=frida-server-%FRIDA_VERSION%-android-arm64.xz
) else if "%ARCH%"=="armeabi-v7a" (
    set FRIDA_SERVER_URL=https://github.com/frida/frida/releases/download/%FRIDA_VERSION%/frida-server-%FRIDA_VERSION%-android-arm.xz
    set FRIDA_SERVER_FILE=frida-server-%FRIDA_VERSION%-android-arm.xz
) else if "%ARCH%"=="x86_64" (
    set FRIDA_SERVER_URL=https://github.com/frida/frida/releases/download/%FRIDA_VERSION%/frida-server-%FRIDA_VERSION%-android-x86_64.xz
    set FRIDA_SERVER_FILE=frida-server-%FRIDA_VERSION%-android-x86_64.xz
) else if "%ARCH%"=="x86" (
    set FRIDA_SERVER_URL=https://github.com/frida/frida/releases/download/%FRIDA_VERSION%/frida-server-%FRIDA_VERSION%-android-x86.xz
    set FRIDA_SERVER_FILE=frida-server-%FRIDA_VERSION%-android-x86.xz
) else (
    echo [ERROR] Unsupported architecture: %ARCH%
    goto :end
)

:: Download Frida server if not already downloaded
if not exist "%FRIDA_SERVER_FILE%" (
    echo [INFO] Downloading from %FRIDA_SERVER_URL%...
    powershell -Command "Invoke-WebRequest -Uri '%FRIDA_SERVER_URL%' -OutFile '%FRIDA_SERVER_FILE%'"
    
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to download Frida server. Please check your internet connection and try again.
        goto :end
    )
) else (
    echo [INFO] Frida server already downloaded
)

:: Extract Frida server
echo [INFO] Extracting Frida server...
where 7z >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    7z e -y "%FRIDA_SERVER_FILE%"
) else (
    echo [WARNING] 7-Zip not found. Please extract %FRIDA_SERVER_FILE% manually.
    goto :end
)

:: Get extracted filename
for /f "tokens=*" %%a in ('dir /b frida-server-%FRIDA_VERSION%-android-*') do set FRIDA_SERVER_EXTRACTED=%%a

:: Push Frida server to device
echo [INFO] Pushing Frida server to device...
adb push "%FRIDA_SERVER_EXTRACTED%" /data/local/tmp/frida-server

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to push Frida server to device. Please check your device connection and try again.
    goto :end
)

:: Set executable permissions
echo [INFO] Setting executable permissions...
adb shell "chmod +x /data/local/tmp/frida-server"

:: Check if Frida server is already running
for /f "tokens=*" %%a in ('adb shell "ps | grep frida-server | wc -l"') do set FRIDA_RUNNING=%%a
if %FRIDA_RUNNING% GTR 0 (
    echo [INFO] Frida server is already running. Stopping it...
    adb shell "killall frida-server"
    timeout /t 2 >nul
)

:: Start Frida server
echo [INFO] Starting Frida server...
adb shell "/data/local/tmp/frida-server &"
timeout /t 2 >nul

:: Verify Frida server is running
for /f "tokens=*" %%a in ('adb shell "ps | grep frida-server | wc -l"') do set FRIDA_RUNNING=%%a
if %FRIDA_RUNNING% GTR 0 (
    echo [SUCCESS] Frida server is running successfully
) else (
    echo [ERROR] Failed to start Frida server. Please check your device and try again.
    goto :end
)

:: Forward Frida server port
echo [INFO] Forwarding Frida server port...
adb forward tcp:27042 tcp:27042

:: Test connection
echo [INFO] Testing connection...
frida-ps -U >nul 2>&1

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to connect to Frida server. Please check your device connection and try again.
    goto :end
)

echo [SUCCESS] Successfully connected to Frida server
echo [SUCCESS] Frida setup completed successfully!
echo.
echo You can now use Frida to instrument apps on your device.
echo Example commands:
echo   frida-ps -U                     # List running processes
echo   frida -U -n com.bearmod         # Attach to BearMod app
echo   frida -U -l script.js -n com.bearmod --no-pause  # Run a script

:end
endlocal
pause
