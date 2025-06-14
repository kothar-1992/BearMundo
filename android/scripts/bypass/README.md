# Bypass Scripts

This directory contains scripts for bypassing various security mechanisms in Android applications.

## Scripts

### root_bypass.js
Bypasses root detection by hooking methods that check for root access:
- Package manager checks
- File system checks
- Command execution checks
- Build property checks

### signature_bypass.js
Bypasses signature verification by hooking into the getPackageInfo method:
- Package signature verification
- APK signature verification
- Certificate verification
- Integrity checks

### ssl_bypass.js
Bypasses SSL certificate pinning by hooking various certificate validation methods:
- OkHttp certificate pinning
- TrustManager certificate validation
- X509TrustManager checks
- Custom certificate validation

## Usage

```bash
# Run individual bypass scripts
frida -U -n com.example.app -l root_bypass.js --no-pause
frida -U -n com.example.app -l signature_bypass.js --no-pause
frida -U -n com.example.app -l ssl_bypass.js --no-pause
```

## Development

When adding new bypass scripts:
1. Follow the existing naming conventions
2. Add proper documentation
3. Include usage examples
4. Test thoroughly before committing
5. Document any version-specific behavior 