#!/bin/bash
# Automated Frida Server Deployment Script
# This script automatically detects device architecture, downloads and deploys Frida server

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║         Bear-Mod Frida Server Setup       ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Check if ADB is installed
if ! command -v adb &> /dev/null; then
    echo -e "${RED}[ERROR] ADB is not installed. Please install Android SDK platform tools.${NC}"
    exit 1
fi

# Check if device is connected
echo -e "${YELLOW}[*] Checking for connected devices...${NC}"
DEVICES=$(adb devices | grep -v "List" | grep "device$")
if [ -z "$DEVICES" ]; then
    echo -e "${RED}[ERROR] No device connected. Please connect a device and try again.${NC}"
    exit 1
fi

# Get device architecture
echo -e "${YELLOW}[*] Detecting device architecture...${NC}"
DEVICE_ARCH=$(adb shell getprop ro.product.cpu.abi)
echo -e "${GREEN}[+] Detected architecture: ${DEVICE_ARCH}${NC}"

# Set Frida version - can be updated as needed
FRIDA_VERSION="16.1.3"
echo -e "${YELLOW}[*] Using Frida version: ${FRIDA_VERSION}${NC}"

# Map Android architecture to Frida architecture
case $DEVICE_ARCH in
    "armeabi-v7a")
        FRIDA_ARCH="arm"
        ;;
    "arm64-v8a")
        FRIDA_ARCH="arm64"
        ;;
    "x86")
        FRIDA_ARCH="x86"
        ;;
    "x86_64")
        FRIDA_ARCH="x86_64"
        ;;
    *)
        echo -e "${RED}[ERROR] Unsupported architecture: ${DEVICE_ARCH}${NC}"
        exit 1
        ;;
esac

# Set Frida server filename
FRIDA_SERVER="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
FRIDA_SERVER_XZ="${FRIDA_SERVER}.xz"
FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER_XZ}"

# Create a directory for Frida server if it doesn't exist
mkdir -p frida-server

# Download Frida server if it doesn't exist
if [ ! -f "frida-server/${FRIDA_SERVER}" ]; then
    echo -e "${YELLOW}[*] Downloading Frida server...${NC}"
    echo -e "${BLUE}[*] URL: ${FRIDA_URL}${NC}"
    
    # Check if wget or curl is available
    if command -v wget &> /dev/null; then
        wget -q --show-progress -O "frida-server/${FRIDA_SERVER_XZ}" "${FRIDA_URL}"
    elif command -v curl &> /dev/null; then
        curl -L -o "frida-server/${FRIDA_SERVER_XZ}" "${FRIDA_URL}"
    else
        echo -e "${RED}[ERROR] Neither wget nor curl is installed. Please install one of them.${NC}"
        exit 1
    fi
    
    # Check if download was successful
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] Failed to download Frida server. Please check your internet connection.${NC}"
        exit 1
    fi
    
    # Extract Frida server
    echo -e "${YELLOW}[*] Extracting Frida server...${NC}"
    if command -v xz &> /dev/null; then
        xz -d "frida-server/${FRIDA_SERVER_XZ}"
    else
        echo -e "${RED}[ERROR] xz is not installed. Please install xz-utils.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] Frida server already exists. Skipping download.${NC}"
fi

# Kill any running Frida server
echo -e "${YELLOW}[*] Killing any running Frida server...${NC}"
adb shell "pkill frida-server" 2>/dev/null

# Push Frida server to device
echo -e "${YELLOW}[*] Pushing Frida server to device...${NC}"
adb push "frida-server/${FRIDA_SERVER}" /data/local/tmp/frida-server

# Set executable permissions
echo -e "${YELLOW}[*] Setting executable permissions...${NC}"
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start Frida server
echo -e "${YELLOW}[*] Starting Frida server...${NC}"
adb shell "su -c '/data/local/tmp/frida-server &'" 2>/dev/null || adb shell "/data/local/tmp/frida-server &"

# Forward port
echo -e "${YELLOW}[*] Forwarding port...${NC}"
adb forward tcp:27042 tcp:27042

# Wait for Frida server to start
echo -e "${YELLOW}[*] Waiting for Frida server to start...${NC}"
sleep 2

# Verify connection
echo -e "${YELLOW}[*] Verifying connection...${NC}"
if command -v frida-ps &> /dev/null; then
    frida-ps -U
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Frida server is running successfully!${NC}"
    else
        echo -e "${RED}[ERROR] Failed to connect to Frida server.${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}[*] frida-ps not found. Please install Frida tools:${NC}"
    echo -e "${BLUE}    pip install frida-tools${NC}"
fi

echo -e "${GREEN}[+] Setup complete!${NC}"
