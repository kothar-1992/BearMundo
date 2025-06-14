# BearMod Assets

This directory contains all the assets used by the BearMod library.

## Directory Structure

- `frida-scripts/` - Frida scripts for runtime analysis and protection
  - `core/` - Core analysis and protection scripts
  - `bypass/` - Bypass and anti-detection scripts
  - `utils/` - Utility scripts and helpers

## Usage

These assets are automatically packaged with the BearMod AAR library and can be accessed at runtime using the Android AssetManager.

## Script Categories

### Core Scripts
- `analyzer.js` - Main analysis script
- `bearmod_analyzer.js` - BearMod-specific analysis

### Bypass Scripts
- `bypass-root.js` - Root detection bypass
- `bypass-signkill.js` - Signature kill bypass
- `bypass-ssl.js` - SSL pinning bypass
- `anti-detection.js` - Anti-detection measures

### Utility Scripts
- Various utility scripts for common operations 