# Utility Scripts

This directory contains utility scripts and helper functions used across the BearMod project.

## Scripts

### common.js
Common utility functions used across all scripts:
- Logging utilities
- Error handling
- Configuration helpers
- Device information
- Process utilities

### remote_logging.js
Remote logging functionality:
- Log formatting
- Log transmission
- Error handling
- Connection management
- Rate limiting

### web_ui.js
Web interface for monitoring and control:
- Real-time monitoring
- Script management
- Configuration interface
- Log viewing
- Status updates

## Usage

These utilities are typically imported and used by other scripts:

```javascript
// Import common utilities
const common = require('./common.js');

// Use logging
common.log('info', 'Application started');

// Get device info
const deviceInfo = common.getDeviceInfo();
```

## Development

When adding new utility scripts:
1. Follow the existing naming conventions
2. Add proper documentation
3. Include usage examples
4. Test thoroughly before committing
5. Ensure cross-platform compatibility 