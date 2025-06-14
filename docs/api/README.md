# Bear-Mod API Documentation

This directory contains documentation for the Bear-Mod API.

## Core API

- [Hooks](core/hooks.md)
- [Memory](core/memory.md)
- [Utils](core/utils.md)

## UI API

- [Components](ui/components.md)

## Frida API

- [Scripts](../frida/scripts.md)
- [Integration](../frida/integration.md)

## Getting Started

To use the Bear-Mod API in your project, follow these steps:

1. Initialize the core:
   ```java
   BearModCore core = BearModCore.getInstance(context);
   if (!core.initialize()) {
       // Handle initialization failure
   }
   ```

2. Use the hook manager:
   ```java
   HookManager hookManager = core.getHookManager();
   hookManager.hookFunction("libc.so", "open", HookType.BEFORE);
   ```

3. Use the memory manager:
   ```java
   long address = NativeBridge.getModuleBase("libc.so");
   byte[] buffer = new byte[100];
   NativeBridge.readMemory(address, buffer, buffer.length);
   ```

## API Reference

### Core Classes

- `BearModCore`: Main entry point for the API
- `NativeBridge`: Bridge between Java and native code
- `HookManager`: Manager for hooking functions
- `Logger`: Utility for logging

### Hook Types

- `HookType.REPLACE`: Replace the original function
- `HookType.BEFORE`: Execute code before the original function
- `HookType.AFTER`: Execute code after the original function

### Native Functions

- `initialize()`: Initialize the native library
- `hookFunction()`: Hook a function
- `readMemory()`: Read memory
- `writeMemory()`: Write memory
- `findPattern()`: Find a pattern in memory
- `getModuleBase()`: Get the base address of a module

## Examples

See the [examples](../examples) directory for complete examples of using the API.
