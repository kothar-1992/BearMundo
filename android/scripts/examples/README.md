# Example Scripts

This directory contains example scripts demonstrating various features and capabilities of BearMod.

## Scripts

### remote_logging_example.js
Example script demonstrating remote logging functionality:
- Basic logging setup
- Log formatting
- Remote transmission
- Error handling
- Configuration

### telegram_logging.js
Example script for sending logs to Telegram:
- Bot setup
- Message formatting
- Error handling
- Rate limiting
- Security considerations

## Usage

These examples can be used as templates for creating new scripts:

```bash
# Run the remote logging example
frida -U -n com.example.app -l remote_logging_example.js --no-pause

# Run the Telegram logging example
frida -U -n com.example.app -l telegram_logging.js --no-pause
```

## Development

When creating new example scripts:
1. Follow the existing naming conventions
2. Add comprehensive documentation
3. Include detailed comments
4. Provide configuration examples
5. Test thoroughly before committing

## Notes

- Examples are for educational purposes
- Modify configurations before use
- Test in a controlled environment
- Follow security best practices 