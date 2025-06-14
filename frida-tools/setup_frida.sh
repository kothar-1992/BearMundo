#!/bin/bash
# Frida Setup Script for BearMod Project
# This script sets up Frida on both your PC and Android device

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Frida version to use
FRIDA_VERSION="16.1.1"

echo -e "${BLUE}=== BearMod Frida Setup ===${NC}"
echo -e "${BLUE}Setting up Frida version ${FRIDA_VERSION}${NC}"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3 and try again.${NC}"
    exit 1
fi

# Install Frida tools on PC
echo -e "${YELLOW}Installing Frida tools on PC...${NC}"
pip3 install frida-tools frida

# Verify installation
if ! command -v frida &> /dev/null; then
    echo -e "${RED}Frida installation failed. Please check your Python setup and try again.${NC}"
    exit 1
fi

FRIDA_VERSION_INSTALLED=$(frida --version)
echo -e "${GREEN}Frida tools installed successfully: ${FRIDA_VERSION_INSTALLED}${NC}"

# Check if ADB is available
if ! command -v adb &> /dev/null; then
    echo -e "${RED}ADB is not available. Please install Android SDK platform tools and try again.${NC}"
    exit 1
fi

# Check if device is connected
echo -e "${YELLOW}Checking for connected Android devices...${NC}"
DEVICES=$(adb devices | grep -v "List" | grep "device" | wc -l)

if [ "$DEVICES" -eq 0 ]; then
    echo -e "${RED}No Android devices connected. Please connect a device and enable USB debugging.${NC}"
    exit 1
fi

echo -e "${GREEN}Found ${DEVICES} connected device(s)${NC}"

# Determine device architecture
echo -e "${YELLOW}Determining device architecture...${NC}"
ARCH=$(adb shell getprop ro.product.cpu.abi)
echo -e "${GREEN}Device architecture: ${ARCH}${NC}"

# Download appropriate Frida server
echo -e "${YELLOW}Downloading Frida server for ${ARCH}...${NC}"

if [ "$ARCH" == "arm64-v8a" ] || [ "$ARCH" == "aarch64" ]; then
    FRIDA_SERVER_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz"
    FRIDA_SERVER_FILE="frida-server-${FRIDA_VERSION}-android-arm64.xz"
elif [ "$ARCH" == "armeabi-v7a" ] || [ "$ARCH" == "armv7l" ] || [ "$ARCH" == "armeabi" ]; then
    FRIDA_SERVER_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm.xz"
    FRIDA_SERVER_FILE="frida-server-${FRIDA_VERSION}-android-arm.xz"
elif [ "$ARCH" == "x86_64" ]; then
    FRIDA_SERVER_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz"
    FRIDA_SERVER_FILE="frida-server-${FRIDA_VERSION}-android-x86_64.xz"
elif [ "$ARCH" == "x86" ]; then
    FRIDA_SERVER_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86.xz"
    FRIDA_SERVER_FILE="frida-server-${FRIDA_VERSION}-android-x86.xz"
else
    echo -e "${RED}Unsupported architecture: ${ARCH}${NC}"
    exit 1
fi

# Download Frida server
if [ ! -f "$FRIDA_SERVER_FILE" ]; then
    echo -e "${YELLOW}Downloading from ${FRIDA_SERVER_URL}...${NC}"
    curl -L -O "$FRIDA_SERVER_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to download Frida server. Please check your internet connection and try again.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}Frida server already downloaded${NC}"
fi

# Extract Frida server
echo -e "${YELLOW}Extracting Frida server...${NC}"
unxz -f "$FRIDA_SERVER_FILE"
FRIDA_SERVER_EXTRACTED="${FRIDA_SERVER_FILE%.xz}"

# Push Frida server to device
echo -e "${YELLOW}Pushing Frida server to device...${NC}"
adb push "$FRIDA_SERVER_EXTRACTED" /data/local/tmp/frida-server

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to push Frida server to device. Please check your device connection and try again.${NC}"
    exit 1
fi

# Set executable permissions
echo -e "${YELLOW}Setting executable permissions...${NC}"
adb shell "chmod +x /data/local/tmp/frida-server"

# Check if Frida server is already running
FRIDA_RUNNING=$(adb shell "ps | grep frida-server" | wc -l)
if [ "$FRIDA_RUNNING" -gt 0 ]; then
    echo -e "${YELLOW}Frida server is already running. Stopping it...${NC}"
    adb shell "killall frida-server"
    sleep 2
fi

# Start Frida server
echo -e "${YELLOW}Starting Frida server...${NC}"
adb shell "/data/local/tmp/frida-server &"
sleep 2

# Verify Frida server is running
FRIDA_RUNNING=$(adb shell "ps | grep frida-server" | wc -l)
if [ "$FRIDA_RUNNING" -gt 0 ]; then
    echo -e "${GREEN}Frida server is running successfully${NC}"
else
    echo -e "${RED}Failed to start Frida server. Please check your device and try again.${NC}"
    exit 1
fi

# Forward Frida server port
echo -e "${YELLOW}Forwarding Frida server port...${NC}"
adb forward tcp:27042 tcp:27042

# Test connection
echo -e "${YELLOW}Testing connection...${NC}"
frida-ps -U > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to connect to Frida server. Please check your device connection and try again.${NC}"
    exit 1
fi

echo -e "${GREEN}Successfully connected to Frida server${NC}"
echo -e "${GREEN}Frida setup completed successfully!${NC}"
echo -e "${BLUE}You can now use Frida to instrument apps on your device.${NC}"
echo -e "${YELLOW}Example commands:${NC}"
echo -e "  frida-ps -U                     # List running processes"
echo -e "  frida -U -n com.bearmod         # Attach to BearMod app"
echo -e "  frida -U -l script.js -n com.bearmod --no-pause  # Run a script"

exit 0
