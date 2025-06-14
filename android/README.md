# BearMod Android Development

This directory contains Android-specific development tools, scripts, and configuration files for the BearMod project.

## Directory Structure

```
android/
├── scripts/           # Android-specific scripts
├── config.js         # Frida configuration
├── run-frida.ps1     # Windows Frida runner
├── run-frida.sh      # Unix Frida runner
├── setup_frida.ps1   # Windows Frida setup
├── setup_frida.sh    # Unix Frida setup
└── README.md         # This file
```

## Scripts

### Frida Setup
- `setup_frida.ps1` - Windows PowerShell script for Frida setup
- `setup_frida.sh` - Unix shell script for Frida setup

### Frida Execution
- `run-frida.ps1` - Windows PowerShell script for running Frida
- `run-frida.sh` - Unix shell script for running Frida

### Configuration
- `config.js` - Frida configuration and settings

## Usage

### Windows
```powershell
# Setup Frida
.\setup_frida.ps1

# Run Frida
.\run-frida.ps1
```

### Unix/Linux/macOS
```bash
# Setup Frida
./setup_frida.sh

# Run Frida
./run-frida.sh
```

## Requirements

- Android SDK
- Frida tools
- Python 3.6+
- PowerShell 5.0+ (Windows)
- Bash (Unix)

## Development

When adding new scripts or configurations:
1. Follow the existing naming conventions
2. Add proper documentation
3. Include both Windows and Unix versions
4. Test thoroughly before committing

## Notes

- Keep scripts updated with the latest Frida version
- Ensure cross-platform compatibility
- Follow security best practices
- Document any environment-specific requirements
