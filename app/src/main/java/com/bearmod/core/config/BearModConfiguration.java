package com.bearmod.core.config;

import android.graphics.Color;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * Configuration class for BearMod AAR library
 * Allows host applications to customize library behavior
 */
public class BearModConfiguration {
    private final SecurityConfig securityConfig;
    private final FeatureConfig featureConfig;
    private final BrandingConfig brandingConfig;
    private final Map<String, Object> customConfig;
    
    private BearModConfiguration(Builder builder) {
        this.securityConfig = builder.securityConfig;
        this.featureConfig = builder.featureConfig;
        this.brandingConfig = builder.brandingConfig;
        this.customConfig = new HashMap<>(builder.customConfig);
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    // Getters
    public SecurityConfig getSecurityConfig() { return securityConfig; }
    public FeatureConfig getFeatureConfig() { return featureConfig; }
    public BrandingConfig getBrandingConfig() { return brandingConfig; }
    public Map<String, Object> getCustomConfig() { return customConfig; }
    
    /**
     * Builder for BearModConfiguration
     */
    public static class Builder {
        private SecurityConfig securityConfig = new SecurityConfig();
        private FeatureConfig featureConfig = new FeatureConfig();
        private BrandingConfig brandingConfig = new BrandingConfig();
        private Map<String, Object> customConfig = new HashMap<>();
        
        public Builder setSecurityConfig(SecurityConfig securityConfig) {
            this.securityConfig = securityConfig;
            return this;
        }
        
        public Builder setFeatureConfig(FeatureConfig featureConfig) {
            this.featureConfig = featureConfig;
            return this;
        }
        
        public Builder setBrandingConfig(BrandingConfig brandingConfig) {
            this.brandingConfig = brandingConfig;
            return this;
        }
        
        public Builder setCustomConfig(String key, Object value) {
            this.customConfig.put(key, value);
            return this;
        }
        
        public BearModConfiguration build() {
            return new BearModConfiguration(this);
        }
    }
    
    /**
     * Security configuration
     */
    public static class SecurityConfig {
        private final SecurityLevel securityLevel;
        private final Set<String> allowedPackages;
        private final Set<String> blockedPackages;
        private final boolean enableStealth;
        private final boolean enableAntiDebug;
        private final boolean enableAntiRoot;
        private final boolean enableAntiEmulator;
        
        public SecurityConfig() {
            this.securityLevel = SecurityLevel.STANDARD;
            this.allowedPackages = new HashSet<>();
            this.blockedPackages = new HashSet<>();
            this.enableStealth = true;
            this.enableAntiDebug = true;
            this.enableAntiRoot = true;
            this.enableAntiEmulator = true;
        }
        
        public SecurityConfig(SecurityLevel securityLevel,
                            Set<String> allowedPackages,
                            Set<String> blockedPackages,
                            boolean enableStealth,
                            boolean enableAntiDebug,
                            boolean enableAntiRoot,
                            boolean enableAntiEmulator) {
            this.securityLevel = securityLevel;
            this.allowedPackages = new HashSet<>(allowedPackages);
            this.blockedPackages = new HashSet<>(blockedPackages);
            this.enableStealth = enableStealth;
            this.enableAntiDebug = enableAntiDebug;
            this.enableAntiRoot = enableAntiRoot;
            this.enableAntiEmulator = enableAntiEmulator;
        }
        
        // Getters
        public SecurityLevel getSecurityLevel() { return securityLevel; }
        public Set<String> getAllowedPackages() { return allowedPackages; }
        public Set<String> getBlockedPackages() { return blockedPackages; }
        public boolean isEnableStealth() { return enableStealth; }
        public boolean isEnableAntiDebug() { return enableAntiDebug; }
        public boolean isEnableAntiRoot() { return enableAntiRoot; }
        public boolean isEnableAntiEmulator() { return enableAntiEmulator; }
    }
    
    /**
     * Feature configuration
     */
    public static class FeatureConfig {
        private final Set<BearModFeature> enabledFeatures;
        private final Map<String, Object> featureSettings;
        
        public FeatureConfig() {
            this.enabledFeatures = new HashSet<>();
            this.featureSettings = new HashMap<>();
        }
        
        public FeatureConfig(Set<BearModFeature> enabledFeatures,
                           Map<String, Object> featureSettings) {
            this.enabledFeatures = new HashSet<>(enabledFeatures);
            this.featureSettings = new HashMap<>(featureSettings);
        }
        
        // Getters
        public Set<BearModFeature> getEnabledFeatures() { return enabledFeatures; }
        public Map<String, Object> getFeatureSettings() { return featureSettings; }
    }
    
    /**
     * Branding configuration
     */
    public static class BrandingConfig {
        private final String appName;
        private final String companyName;
        private final int logoResourceId;
        private final ColorScheme colorScheme;
        
        public BrandingConfig() {
            this.appName = "BearMod";
            this.companyName = "BearMod Security";
            this.logoResourceId = 0;
            this.colorScheme = ColorScheme.DEFAULT;
        }
        
        public BrandingConfig(String appName,
                            String companyName,
                            int logoResourceId,
                            ColorScheme colorScheme) {
            this.appName = appName;
            this.companyName = companyName;
            this.logoResourceId = logoResourceId;
            this.colorScheme = colorScheme;
        }
        
        // Getters
        public String getAppName() { return appName; }
        public String getCompanyName() { return companyName; }
        public int getLogoResourceId() { return logoResourceId; }
        public ColorScheme getColorScheme() { return colorScheme; }
    }
    
    /**
     * Security levels
     */
    public enum SecurityLevel {
        BASIC,      // Basic security features
        STANDARD,   // Standard security features
        HIGH,       // High security features
        ENTERPRISE  // Enterprise security features
    }
    
    /**
     * Available features
     */
    public enum BearModFeature {
        SSL_BYPASS,             // SSL pinning bypass
        ROOT_BYPASS,           // Root detection bypass
        DEBUG_BYPASS,          // Debug detection bypass
        EMULATOR_BYPASS,       // Emulator detection bypass
        SIGNATURE_BYPASS,      // Signature verification bypass
        FRIDA_DETECTION,       // Frida detection
        MEMORY_PROTECTION,     // Memory protection
        REAL_TIME_ANALYSIS,    // Real-time analysis
        SECURITY_MONITORING,   // Security monitoring
        CUSTOM_HOOKS          // Custom hook support
    }
    
    /**
     * Color schemes
     */
    public enum ColorScheme {
        DEFAULT,
        BLUE_THEME,
        DARK_THEME,
        LIGHT_THEME,
        CUSTOM
    }
} 