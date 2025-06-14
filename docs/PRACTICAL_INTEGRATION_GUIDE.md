# BearMod AAR Practical Integration Guide

## 🚀 Quick Start Integration

### Step 1: Add AAR Dependency

```kotlin
// Host app build.gradle.kts
dependencies {
    implementation(files("libs/bearmod-library-1.0.0.aar"))
    
    // Required dependencies
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.code.gson:gson:2.10.1")
}
```

### Step 2: Initialize in Application Class

```java
// MyApplication.java
public class MyApplication extends Application {
    
    private BearModAuthenticationManager authManager;
    private String bearModSessionToken;
    
    @Override
    public void onCreate() {
        super.onCreate();
        
        // Initialize BearMod AAR
        initializeBearMod();
    }
    
    private void initializeBearMod() {
        authManager = BearModAuthenticationManager.getInstance();
        
        // Create host context with your app details
        HostContext hostContext = createHostContext();
        
        // Create authentication request
        AuthenticationRequest authRequest = AuthenticationRequest.builder()
            .setHostContext(hostContext)
            .setConfiguration(createBearModConfiguration())
            .build();
        
        // Authenticate with BearMod
        authManager.authenticateHostApplication(this, authRequest)
            .thenAccept(this::handleBearModAuth)
            .exceptionally(throwable -> {
                Log.e("BearMod", "Authentication failed", throwable);
                return null;
            });
    }
    
    private HostContext createHostContext() {
        return new HostContext(
            "myapp_v1_" + BuildConfig.VERSION_CODE,  // Unique host ID
            getPackageName(),                        // Package name
            getString(R.string.app_name),           // App name
            BuildConfig.VERSION_NAME,               // Version
            SignatureVerifier.getAppSignature(this), // App signature
            BuildConfig.BEARMOD_SECRET_KEY          // Secret key
        );
    }
    
    private void handleBearModAuth(AuthenticationResult result) {
        if (result.isAuthenticated()) {
            bearModSessionToken = result.getSessionToken();
            Log.i("BearMod", "Authenticated with level: " + result.getAuthLevel());
            
            // Store container reference for later use
            BearModContainer container = result.getContainer();
            BearModManager.getInstance().setContainer(container);
        } else {
            Log.e("BearMod", "Authentication failed: " + result.getErrorMessage());
        }
    }
}
```

## 🔐 Authentication Strategies

### Strategy 1: Signature-Only Authentication (Basic)

```java
// Basic authentication using only app signature
public class BasicAuthStrategy {
    
    public void authenticate(Context context) {
        HostContext hostContext = new HostContext(
            "basic_host_" + context.getPackageName(),
            context.getPackageName(),
            "Basic App",
            "1.0.0",
            SignatureVerifier.getAppSignature(context),
            null // No secret key for basic auth
        );
        
        AuthenticationRequest request = AuthenticationRequest.builder()
            .setHostContext(hostContext)
            .setConfiguration(createBasicConfig())
            .build();
        
        // This will provide BASIC auth level with limited permissions
        BearModAuthenticationManager.getInstance()
            .authenticateHostApplication(context, request);
    }
    
    private BearModConfiguration createBasicConfig() {
        return BearModConfiguration.builder()
            .setFeatures(new FeatureConfig(
                Set.of(BearModFeature.SIGNATURE_BYPASS), // Limited features
                Map.of()
            ))
            .setSecurity(new SecurityConfig(
                SecurityLevel.BASIC,
                Set.of(getPackageName()), // Only allow own package
                Set.of() // No restrictions
            ))
            .build();
    }
}
```

### Strategy 2: KeyAuth Integration (Premium)

```java
// KeyAuth authentication for premium features
public class KeyAuthStrategy {
    
    public void authenticateWithKeyAuth(Context context, String username, String password) {
        HostContext hostContext = createHostContext(context);
        
        AuthenticationRequest request = AuthenticationRequest.builder()
            .setHostContext(hostContext)
            .setKeyAuthCredentials(username, password)
            .setConfiguration(createPremiumConfig())
            .build();
        
        BearModAuthenticationManager.getInstance()
            .authenticateHostApplication(context, request)
            .thenAccept(result -> {
                if (result.isAuthenticated()) {
                    // Premium features available
                    enablePremiumFeatures(result.getContainer());
                }
            });
    }
    
    private void enablePremiumFeatures(BearModContainer container) {
        IsolatedHookManager hookManager = container.getHookManager();
        
        // Enable all bypass features
        hookManager.enableSSLBypass();
        hookManager.enableRootDetectionBypass();
        hookManager.enableSignatureBypass();
        hookManager.enableFridaDetectionBypass();
        
        // Start real-time security analysis
        container.getSecurityAnalyzer().startRealTimeAnalysis();
    }
}
```

### Strategy 3: Hybrid Authentication (Enterprise)

```java
// Combination of signature + token + KeyAuth for maximum security
public class HybridAuthStrategy {
    
    public void authenticateHybrid(Context context, String keyAuthToken, String customToken) {
        HostContext hostContext = createSecureHostContext(context);
        
        AuthenticationRequest request = AuthenticationRequest.builder()
            .setHostContext(hostContext)
            .setAuthToken(customToken)
            .setKeyAuthCredentials(extractKeyAuthCredentials(keyAuthToken))
            .setRequireChallenge(true) // Enable crypto challenge
            .setConfiguration(createEnterpriseConfig())
            .build();
        
        BearModAuthenticationManager.getInstance()
            .authenticateHostApplication(context, request)
            .thenAccept(this::handleEnterpriseAuth);
    }
    
    private void handleEnterpriseAuth(AuthenticationResult result) {
        if (result.isAuthenticated() && result.getAuthLevel() == AuthLevel.ENTERPRISE) {
            // Full enterprise features available
            BearModContainer container = result.getContainer();
            
            // Enable all features
            enableAllFeatures(container);
            
            // Setup custom plugins
            setupEnterprisePlugins(container);
            
            // Configure advanced security policies
            configureAdvancedSecurity(container);
        }
    }
}
```

## 🏢 Multi-Tenant Configuration Examples

### Banking App Configuration

```java
public class BankingAppConfig {
    
    public static BearModConfiguration createBankingConfig() {
        return BearModConfiguration.builder()
            .setBranding(new BrandingConfig(
                "SecureBank Security",
                "SecureBank Corp",
                R.drawable.bank_logo,
                ColorScheme.CORPORATE_BLUE
            ))
            .setFeatures(new FeatureConfig(
                Set.of(
                    BearModFeature.SSL_BYPASS,
                    BearModFeature.ROOT_DETECTION_BYPASS,
                    BearModFeature.SECURITY_ANALYSIS
                ),
                Map.of(
                    "enable_transaction_monitoring", true,
                    "enable_fraud_detection", true,
                    "log_level", "INFO"
                )
            ))
            .setSecurity(new SecurityConfig(
                SecurityLevel.HIGH,
                Set.of("com.securebank.*", "com.banking.*"),
                Set.of("com.malware.*", "com.suspicious.*"),
                List.of(
                    new SecurityRule("block_root_access", "DENY"),
                    new SecurityRule("require_ssl", "ENFORCE")
                )
            ))
            .setUI(new UIConfig(
                R.style.BankingTheme,
                Map.of(
                    "primary_color", "#1976D2",
                    "accent_color", "#FFC107"
                )
            ))
            .build();
    }
}
```

### Gaming App Configuration

```java
public class GamingAppConfig {
    
    public static BearModConfiguration createGamingConfig() {
        return BearModConfiguration.builder()
            .setBranding(new BrandingConfig(
                "GameGuard",
                "Epic Games Studio",
                R.drawable.game_logo,
                ColorScheme.GAMING_DARK
            ))
            .setFeatures(new FeatureConfig(
                Set.of(
                    BearModFeature.FRIDA_DETECTION_BYPASS,
                    BearModFeature.CUSTOM_HOOKS,
                    BearModFeature.REAL_TIME_MONITORING
                ),
                Map.of(
                    "enable_cheat_detection", true,
                    "enable_memory_protection", true,
                    "performance_mode", "HIGH"
                )
            ))
            .setSecurity(new SecurityConfig(
                SecurityLevel.MEDIUM,
                Set.of("com.epicgames.*", "com.gameengine.*"),
                Set.of("com.cheat.*", "com.hack.*"),
                List.of(
                    new SecurityRule("detect_memory_modification", "ALERT"),
                    new SecurityRule("block_debugging", "ENFORCE")
                )
            ))
            .build();
    }
}
```

### E-commerce App Configuration

```java
public class EcommerceAppConfig {
    
    public static BearModConfiguration createEcommerceConfig() {
        return BearModConfiguration.builder()
            .setBranding(new BrandingConfig(
                "ShopSecure",
                "MegaShop Inc",
                R.drawable.shop_logo,
                ColorScheme.RETAIL_GREEN
            ))
            .setFeatures(new FeatureConfig(
                Set.of(
                    BearModFeature.SSL_BYPASS,
                    BearModFeature.SIGNATURE_BYPASS,
                    BearModFeature.SECURITY_ANALYSIS
                ),
                Map.of(
                    "enable_payment_protection", true,
                    "enable_data_encryption", true,
                    "track_user_behavior", false
                )
            ))
            .setSecurity(new SecurityConfig(
                SecurityLevel.HIGH,
                Set.of("com.megashop.*", "com.payment.*"),
                Set.of("com.fraud.*", "com.phishing.*"),
                List.of(
                    new SecurityRule("protect_payment_data", "ENFORCE"),
                    new SecurityRule("validate_certificates", "ENFORCE")
                )
            ))
            .build();
    }
}
```

## 🎨 White-Label Customization

### Theme Customization

```java
// Custom theme configuration for white-label apps
public class WhiteLabelThemes {
    
    public static UIConfig createCustomTheme(String brandName, int logoRes, String primaryColor) {
        return new UIConfig(
            R.style.CustomBearModTheme,
            Map.of(
                "brand_name", brandName,
                "logo_resource", String.valueOf(logoRes),
                "primary_color", primaryColor,
                "secondary_color", adjustColorBrightness(primaryColor, 0.8f),
                "background_color", "#FFFFFF",
                "text_color", "#333333"
            )
        );
    }
    
    public static BrandingConfig createBranding(String appName, String companyName, 
                                              int logoRes, Map<String, String> customStrings) {
        return new BrandingConfig(
            appName,
            companyName,
            logoRes,
            ColorScheme.CUSTOM,
            customStrings
        );
    }
}
```

### Feature Customization

```java
// Customizable feature sets for different clients
public class FeatureCustomization {
    
    public static FeatureConfig createBasicFeatureSet() {
        return new FeatureConfig(
            Set.of(
                BearModFeature.SSL_BYPASS,
                BearModFeature.SIGNATURE_BYPASS
            ),
            Map.of(
                "max_hooks", 10,
                "enable_logging", false
            )
        );
    }
    
    public static FeatureConfig createPremiumFeatureSet() {
        return new FeatureConfig(
            Set.of(
                BearModFeature.SSL_BYPASS,
                BearModFeature.ROOT_DETECTION_BYPASS,
                BearModFeature.SIGNATURE_BYPASS,
                BearModFeature.FRIDA_DETECTION_BYPASS,
                BearModFeature.REAL_TIME_MONITORING
            ),
            Map.of(
                "max_hooks", 100,
                "enable_logging", true,
                "enable_analytics", true
            )
        );
    }
    
    public static FeatureConfig createEnterpriseFeatureSet() {
        return new FeatureConfig(
            Set.of(BearModFeature.values()), // All features
            Map.of(
                "max_hooks", -1, // Unlimited
                "enable_logging", true,
                "enable_analytics", true,
                "enable_custom_plugins", true,
                "enable_api_access", true
            )
        );
    }
}
```

## 🔧 Container Management

### Container Lifecycle Management

```java
public class BearModManager {
    
    private static BearModManager instance;
    private BearModContainer currentContainer;
    private String currentSessionToken;
    
    public static BearModManager getInstance() {
        if (instance == null) {
            instance = new BearModManager();
        }
        return instance;
    }
    
    public void setContainer(BearModContainer container) {
        this.currentContainer = container;
    }
    
    public IsolatedHookManager getHookManager() {
        return currentContainer != null ? currentContainer.getHookManager() : null;
    }
    
    public IsolatedSecurityAnalyzer getSecurityAnalyzer() {
        return currentContainer != null ? currentContainer.getSecurityAnalyzer() : null;
    }
    
    public void cleanup() {
        if (currentContainer != null) {
            currentContainer.cleanup();
            currentContainer = null;
        }
        
        if (currentSessionToken != null) {
            BearModAuthenticationManager.getInstance()
                .invalidateSession(currentSessionToken);
            currentSessionToken = null;
        }
    }
}
```

This comprehensive integration guide provides practical examples for implementing BearMod AAR in different types of host applications with proper authentication, multi-tenant support, and white-label customization capabilities.
