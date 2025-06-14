#!/usr/bin/env python3
"""
Bear-Mod Frida Launcher

This script provides a convenient way to launch Frida scripts
for the Bear-Mod project.

DISCLAIMER:
Bear-Mod is designed for security researchers, app developers, and educational purposes only.
Users must:
1. Only analyze applications they own or have explicit permission to test
2. Respect intellectual property rights and terms of service
3. Use findings responsibly through proper disclosure channels
4. Not use this tool to access unauthorized content or services

Misuse of this tool may violate laws including but not limited to the Computer Fraud and Abuse Act,
Digital Millennium Copyright Act, and equivalent legislation in other jurisdictions.
"""

import os
import sys
import time
import argparse
import frida
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"frida_launcher_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    ]
)
logger = logging.getLogger("FridaLauncher")

# Default script directory
SCRIPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")

def on_message(message, data):
    """
    Callback for Frida messages
    """
    if message['type'] == 'send':
        logger.info("[FRIDA] %s", message['payload'])
    elif message['type'] == 'error':
        logger.error("[FRIDA ERROR] %s", message['stack'])
    else:
        logger.debug("[FRIDA] %s", message)

def list_scripts():
    """
    List available scripts
    """
    scripts = []
    for filename in os.listdir(SCRIPT_DIR):
        if filename.endswith(".js"):
            script_path = os.path.join(SCRIPT_DIR, filename)
            with open(script_path, 'r') as f:
                first_line = f.readline().strip()
                description = first_line.replace('/**', '').replace('*/', '').replace('*', '').strip()

            scripts.append({
                "name": filename,
                "path": script_path,
                "description": description
            })

    return scripts

def list_devices():
    """
    List available devices
    """
    devices = []

    try:
        # Get USB devices
        usb_devices = frida.enumerate_devices()
        for device in usb_devices:
            devices.append({
                "id": device.id,
                "name": device.name,
                "type": device.type
            })
    except Exception as e:
        logger.error("Error enumerating devices: %s", e)

    return devices

def list_processes(device_id=None):
    """
    List processes on the device
    """
    processes = []

    try:
        # Get device
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device()

        # Get processes
        device_processes = device.enumerate_processes()
        for process in device_processes:
            processes.append({
                "pid": process.pid,
                "name": process.name
            })
    except Exception as e:
        logger.error("Error enumerating processes: %s", e)

    return processes

def attach_to_process(process_name, script_path, device_id=None, spawn=False):
    """
    Attach to a process and inject a script
    """
    try:
        # Get device
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device()

        logger.info("Using device: %s", device.name)

        # Get process
        if spawn:
            logger.info("Spawning process: %s", process_name)
            pid = device.spawn([process_name])
            session = device.attach(pid)
            logger.info("Attached to process (PID: %d)", pid)
        else:
            logger.info("Attaching to process: %s", process_name)
            session = device.attach(process_name)
            logger.info("Attached to process")

        # Load script
        with open(script_path, 'r') as f:
            script_content = f.read()

        logger.info("Loading script: %s", script_path)
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()

        # Resume process if spawned
        if spawn:
            logger.info("Resuming process")
            device.resume(pid)

        logger.info("Script loaded successfully")

        # Keep the script running
        logger.info("Press Ctrl+C to stop")
        sys.stdin.read()
    except KeyboardInterrupt:
        logger.info("Exiting...")
    except Exception as e:
        logger.error("Error: %s", e)
        return False

    return True

def main():
    """
    Main function
    """
    parser = argparse.ArgumentParser(description="Bear-Mod Frida Launcher")

    # Command subparsers
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List scripts command
    list_scripts_parser = subparsers.add_parser("list-scripts", help="List available scripts")

    # List devices command
    list_devices_parser = subparsers.add_parser("list-devices", help="List available devices")

    # List processes command
    list_processes_parser = subparsers.add_parser("list-processes", help="List processes on the device")
    list_processes_parser.add_argument("-d", "--device", help="Device ID")

    # Run command
    run_parser = subparsers.add_parser("run", help="Run a script")
    run_parser.add_argument("-p", "--package", required=True, help="Target package name")
    run_parser.add_argument("-s", "--script", required=True, help="Script name or path")
    run_parser.add_argument("-d", "--device", help="Device ID")
    run_parser.add_argument("--spawn", action="store_true", help="Spawn the process instead of attaching")

    # Parse arguments
    args = parser.parse_args()

    # Execute command
    if args.command == "list-scripts":
        scripts = list_scripts()
        print("\nAvailable scripts:")
        for i, script in enumerate(scripts):
            print(f"{i+1}. {script['name']}")
            print(f"   {script['description']}")
        print()
    elif args.command == "list-devices":
        devices = list_devices()
        print("\nAvailable devices:")
        for i, device in enumerate(devices):
            print(f"{i+1}. {device['name']} ({device['id']}) - {device['type']}")
        print()
    elif args.command == "list-processes":
        processes = list_processes(args.device)
        print("\nProcesses:")
        for i, process in enumerate(processes):
            print(f"{i+1}. {process['name']} (PID: {process['pid']})")
        print()
    elif args.command == "run":
        # Find script path
        script_path = args.script
        if not os.path.isfile(script_path):
            # Try to find in script directory
            script_path = os.path.join(SCRIPT_DIR, args.script)
            if not os.path.isfile(script_path):
                # Try adding .js extension
                script_path = os.path.join(SCRIPT_DIR, args.script + ".js")
                if not os.path.isfile(script_path):
                    logger.error("Script not found: %s", args.script)
                    return 1

        # Run script
        attach_to_process(args.package, script_path, args.device, args.spawn)
    else:
        parser.print_help()

    return 0

if __name__ == "__main__":
    sys.exit(main())
