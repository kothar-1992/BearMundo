@echo off
setlocal enabledelayedexpansion

echo ===== BearMod Frida Tools =====
echo.
echo 1. Run BearMod Analyzer
echo 2. Run SDK Analyzer
echo 3. Run Offset Finder
echo 4. List Running Processes
echo 5. Attach to BearMod App
echo 6. Setup Frida
echo 7. Exit
echo.

set /p choice=Enter your choice (1-7): 

if "%choice%"=="1" (
    echo Running BearMod Analyzer...
    frida -U -n com.bearmod -l bearmod_analyzer.js --no-pause
) else if "%choice%"=="2" (
    echo Running SDK Analyzer...
    frida -U -n com.bearmod -l sdk_analyzer.js --no-pause
) else if "%choice%"=="3" (
    echo Running Offset Finder...
    frida -U -n com.bearmod -l offset_finder.js --no-pause
) else if "%choice%"=="4" (
    echo Listing Running Processes...
    frida-ps -U
    pause
    %0
) else if "%choice%"=="5" (
    echo Attaching to BearMod App...
    frida -U -n com.bearmod
) else if "%choice%"=="6" (
    echo Setting up Frida...
    call setup_frida.bat
    %0
) else if "%choice%"=="7" (
    echo Exiting...
    goto :end
) else (
    echo Invalid choice. Please try again.
    pause
    %0
)

:end
endlocal
