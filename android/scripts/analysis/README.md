# Analysis Scripts

This directory contains scripts for analyzing Android applications and their behavior.

## Scripts

### app_analyzer.js
Main analysis script that provides comprehensive analysis of Android applications:
- Security mechanism detection
- Network communication analysis
- Native library analysis
- Class and method discovery
- Resource analysis
- Permission analysis

## Usage

```bash
# Run the analyzer
frida -U -n com.example.app -l app_analyzer.js --no-pause
```

## Output

The analyzer provides detailed information about:
- Security mechanisms in place
- Network endpoints and protocols
- Native libraries and their functions
- Interesting classes and methods
- Resource usage and permissions
- Potential vulnerabilities

## Development

When adding new analysis scripts:
1. Follow the existing naming conventions
2. Add proper documentation
3. Include usage examples
4. Test thoroughly before committing 