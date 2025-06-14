# BearMod Android Scripts

This directory contains Frida scripts and utilities for Android security analysis and dynamic instrumentation.

## Directory Structure

```
scripts/
├── analysis/     # Analysis scripts
├── bypass/       # Bypass scripts
├── examples/     # Example scripts
├── stealth/      # Stealth mode scripts
├── utils/        # Utility scripts
└── main.js       # Main script loader
```

## Script Categories

### Analysis Scripts
- Application behavior analysis
- Security mechanism detection
- Network communication analysis
- Native library analysis

### Bypass Scripts
- Root detection bypass
- Signature verification bypass
- SSL pinning bypass
- Anti-debug bypass

### Stealth Scripts
- Anti-detection measures
- Frida detection prevention
- Debugger detection bypass
- Memory protection

### Utility Scripts
- Common functions
- Helper methods
- Logging utilities
- Configuration helpers

### Examples
- Sample scripts
- Usage examples
- Tutorial scripts
- Reference implementations

## Usage

### Main Script
The `main.js` script provides a unified interface to load all BearMod modules. Configure which modules to load by modifying the configuration object:

```javascript
const config = {
    enableStealth: true,
    bypassSignature: true,
    bypassSSLPinning: true,
    bypassRootDetection: true,
    analyzeApp: true,
    logLevel: "info" // debug, info, warn, error
};
```

### Running Scripts
```bash
# Using main script
frida -U -n com.example.app -l main.js --no-pause

# Using individual scripts
frida -U -n com.example.app -l analysis/app_analyzer.js --no-pause
frida -U -n com.example.app -l bypass/signature_bypass.js --no-pause
```

## Development

When adding new scripts:
1. Place them in the appropriate category directory
2. Follow the existing naming conventions
3. Add proper documentation
4. Include usage examples
5. Test thoroughly before committing

## Notes

- Keep scripts updated with the latest Android versions
- Test on multiple Android versions
- Document any version-specific behavior
- Follow security best practices 