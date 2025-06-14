#!/bin/bash
# Bear-Mod Frida Launcher
# This script helps set up and run Frida with Bear-Mod scripts

# Default values
PACKAGE_NAME=""
SCRIPT="main.js"
SETUP=false
LIST=false
HELP=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--package)
            PACKAGE_NAME="$2"
            shift 2
            ;;
        -s|--script)
            SCRIPT="$2"
            shift 2
            ;;
        --setup)
            SETUP=true
            shift
            ;;
        --list)
            LIST=true
            shift
            ;;
        -h|--help)
            HELP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Display help
if [ "$HELP" = true ]; then
    echo -e "\e[32mBear-Mod Frida Launcher\e[0m"
    echo -e "\e[33mUsage: ./run-frida.sh [options]\e[0m"
    echo ""
    echo -e "\e[33mOptions:\e[0m"
    echo -e "  -p, --package <name>  Target package name (e.g., com.example.app)"
    echo -e "  -s, --script <path>    Script to run (default: main.js)"
    echo -e "  --setup                Set up Frida server on device"
    echo -e "  --list                 List running processes on device"
    echo -e "  -h, --help             Display this help message"
    echo ""
    echo -e "\e[33mExamples:\e[0m"
    echo -e "  ./run-frida.sh --setup"
    echo -e "  ./run-frida.sh --list"
    echo -e "  ./run-frida.sh -p com.example.app -s scripts/bypass/signature_bypass.js"
    exit 0
fi

# Set up Frida server
if [ "$SETUP" = true ]; then
    echo -e "\e[32mSetting up Frida server on device...\e[0m"
    
    # Check if device is connected
    if ! adb devices | grep -q "device$"; then
        echo -e "\e[31mNo device connected. Please connect a device and try again.\e[0m"
        exit 1
    fi
    
    # Check if frida-server exists in frida-server directory
    FRIDA_SERVER_PATH="$(dirname "$0")/frida-server"
    FRIDA_SERVER_FILES=($(ls -1 "$FRIDA_SERVER_PATH"/frida-server-* 2>/dev/null))
    
    if [ ${#FRIDA_SERVER_FILES[@]} -eq 0 ]; then
        echo -e "\e[31mNo Frida server found in frida-server directory.\e[0m"
        echo -e "\e[33mPlease download the appropriate Frida server for your device from:\e[0m"
        echo -e "\e[33mhttps://github.com/frida/frida/releases\e[0m"
        echo -e "\e[33mand place it in the frida-server directory.\e[0m"
        exit 1
    fi
    
    # Use the latest Frida server
    FRIDA_SERVER_NAME=$(basename "${FRIDA_SERVER_FILES[0]}")
    
    echo -e "\e[32mUsing Frida server: $FRIDA_SERVER_NAME\e[0m"
    
    # Kill any running Frida server
    echo -e "\e[33mKilling any running Frida server...\e[0m"
    adb shell "pkill frida-server" 2>/dev/null
    
    # Push Frida server to device
    echo -e "\e[33mPushing Frida server to device...\e[0m"
    adb push "$FRIDA_SERVER_PATH/$FRIDA_SERVER_NAME" /data/local/tmp/frida-server
    
    # Set executable permissions
    echo -e "\e[33mSetting executable permissions...\e[0m"
    adb shell "chmod 755 /data/local/tmp/frida-server"
    
    # Start Frida server
    echo -e "\e[33mStarting Frida server...\e[0m"
    adb shell "/data/local/tmp/frida-server &"
    
    # Forward port
    echo -e "\e[33mForwarding port...\e[0m"
    adb forward tcp:27042 tcp:27042
    
    # Verify connection
    echo -e "\e[33mVerifying connection...\e[0m"
    frida-ps -U
    
    echo -e "\e[32mFrida setup complete!\e[0m"
    exit 0
fi

# List processes
if [ "$LIST" = true ]; then
    echo -e "\e[32mListing processes on device...\e[0m"
    frida-ps -U
    exit 0
fi

# Run script
if [ -z "$PACKAGE_NAME" ]; then
    echo -e "\e[31mPlease specify a package name with -p or --package\e[0m"
    echo -e "\e[33mUse -h or --help for usage information\e[0m"
    exit 1
fi

# Check if script exists
SCRIPT_PATH="$(dirname "$0")/$SCRIPT"
if [ ! -f "$SCRIPT_PATH" ]; then
    echo -e "\e[31mScript not found: $SCRIPT_PATH\e[0m"
    exit 1
fi

# Run Frida with script
echo -e "\e[32mRunning Frida with script: $SCRIPT_PATH\e[0m"
echo -e "\e[32mTarget package: $PACKAGE_NAME\e[0m"
frida -U -n "$PACKAGE_NAME" -l "$SCRIPT_PATH" --no-pause

echo "Press Enter to continue..."
read
