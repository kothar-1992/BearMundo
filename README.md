# BearMundo

BearMundo is an Android application that provides a modern and intuitive user experience.

## Features

- Modern Material Design UI
- MVVM Architecture
- Dependency Injection with Hilt
- Navigation Component
- Unit and UI Testing

## Requirements

- Android Studio Hedgehog (2023.1.1) or newer
- JDK 17
- Android SDK 34
- Gradle 8.0+

## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/yourusername/BearMundo.git
```

2. Open the project in Android Studio

3. Sync the project with Gradle files

4. Run the application on an emulator or physical device

## Project Structure

```
app/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/bearmundo/
│   │   │       ├── data/
│   │   │       ├── di/
│   │   │       ├── ui/
│   │   │       └── utils/
│   │   └── res/
│   └── test/
└── build.gradle
```

## Building the Project

### Debug Build
```bash
./gradlew assembleDebug
```

### Release Build
```bash
./gradlew assembleRelease
```

## Testing

### Unit Tests
```bash
./gradlew test
```

### Instrumentation Tests
```bash
./gradlew connectedAndroidTest
```

## CI/CD

The project uses GitHub Actions for continuous integration. The workflow includes:
- Building the project
- Running unit tests
- Running instrumentation tests
- Code quality checks
- Release signing

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

- All sensitive data is stored securely using Android's EncryptedSharedPreferences
- Network communications are secured using TLS
- API keys and secrets are stored in environment variables
- Regular security audits are performed

## Support

For support, please:
1. Check the [documentation](docs/)
2. Search for existing issues
3. Create a new issue if needed

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
