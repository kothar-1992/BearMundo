package com.bearmod.core.native;

import android.content.Context;
import android.util.Log;

import com.bearmod.core.constants.BearModConstants;

/**
 * Native interface for BearMod library
 */
public final class BearModNative {
    private static final String TAG = "BearModNative";
    
    static {
        try {
            System.loadLibrary(BearModConstants.NATIVE_LIB_NAME);
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library", e);
        }
    }
    
    private BearModNative() {
        // Prevent instantiation
    }
    
    /**
     * Initialize native library
     * @param context Application context
     * @return true if successful, false otherwise
     */
    public static native boolean initialize(Context context);
    
    /**
     * Cleanup native library
     */
    public static native void cleanup();
    
    /**
     * Check if native library is initialized
     * @return true if initialized, false otherwise
     */
    public static native boolean isInitialized();
    
    /**
     * Get native library version
     * @return Native library version
     */
    public static native String getVersion();
    
    /**
     * Get native library version code
     * @return Native library version code
     */
    public static native int getVersionCode();
    
    /**
     * Check if native library is supported
     * @return true if supported, false otherwise
     */
    public static native boolean isSupported();
    
    /**
     * Check if native library is available
     * @return true if available, false otherwise
     */
    public static native boolean isAvailable();
    
    /**
     * Check if native library is loaded
     * @return true if loaded, false otherwise
     */
    public static native boolean isLoaded();
    
    /**
     * Check if native library is ready
     * @return true if ready, false otherwise
     */
    public static native boolean isReady();
    
    /**
     * Check if native library is busy
     * @return true if busy, false otherwise
     */
    public static native boolean isBusy();
    
    /**
     * Check if native library is idle
     * @return true if idle, false otherwise
     */
    public static native boolean isIdle();
    
    /**
     * Check if native library is active
     * @return true if active, false otherwise
     */
    public static native boolean isActive();
    
    /**
     * Check if native library is inactive
     * @return true if inactive, false otherwise
     */
    public static native boolean isInactive();
    
    /**
     * Check if native library is enabled
     * @return true if enabled, false otherwise
     */
    public static native boolean isEnabled();
    
    /**
     * Check if native library is disabled
     * @return true if disabled, false otherwise
     */
    public static native boolean isDisabled();
    
    /**
     * Enable native library
     * @return true if successful, false otherwise
     */
    public static native boolean enable();
    
    /**
     * Disable native library
     * @return true if successful, false otherwise
     */
    public static native boolean disable();
    
    /**
     * Start native library
     * @return true if successful, false otherwise
     */
    public static native boolean start();
    
    /**
     * Stop native library
     * @return true if successful, false otherwise
     */
    public static native boolean stop();
    
    /**
     * Pause native library
     * @return true if successful, false otherwise
     */
    public static native boolean pause();
    
    /**
     * Resume native library
     * @return true if successful, false otherwise
     */
    public static native boolean resume();
    
    /**
     * Reset native library
     * @return true if successful, false otherwise
     */
    public static native boolean reset();
    
    /**
     * Configure native library
     * @param key Configuration key
     * @param value Configuration value
     * @return true if successful, false otherwise
     */
    public static native boolean configure(String key, String value);
    
    /**
     * Get native library configuration
     * @param key Configuration key
     * @return Configuration value or null if not found
     */
    public static native String getConfiguration(String key);
    
    /**
     * Set native library configuration
     * @param key Configuration key
     * @param value Configuration value
     * @return true if successful, false otherwise
     */
    public static native boolean setConfiguration(String key, String value);
    
    /**
     * Remove native library configuration
     * @param key Configuration key
     * @return true if successful, false otherwise
     */
    public static native boolean removeConfiguration(String key);
    
    /**
     * Clear native library configuration
     * @return true if successful, false otherwise
     */
    public static native boolean clearConfiguration();
    
    /**
     * Check if native library configuration contains key
     * @param key Configuration key
     * @return true if configuration contains key, false otherwise
     */
    public static native boolean containsConfiguration(String key);
    
    /**
     * Get native library configuration count
     * @return Number of configuration entries
     */
    public static native int getConfigurationCount();
    
    /**
     * Get native library configuration keys
     * @return Array of configuration keys
     */
    public static native String[] getConfigurationKeys();
    
    /**
     * Get native library configuration values
     * @return Array of configuration values
     */
    public static native String[] getConfigurationValues();
    
    /**
     * Get native library configuration entries
     * @return Array of configuration entries
     */
    public static native String[] getConfigurationEntries();
    
    /**
     * Get native library configuration map
     * @return Map of configuration entries
     */
    public static native String[] getConfigurationMap();
    
    /**
     * Get native library configuration string
     * @return Configuration string
     */
    public static native String getConfigurationString();
    
    /**
     * Get native library configuration JSON
     * @return Configuration JSON
     */
    public static native String getConfigurationJson();
    
    /**
     * Get native library configuration XML
     * @return Configuration XML
     */
    public static native String getConfigurationXml();
    
    /**
     * Get native library configuration YAML
     * @return Configuration YAML
     */
    public static native String getConfigurationYaml();
    
    /**
     * Get native library configuration properties
     * @return Configuration properties
     */
    public static native String getConfigurationProperties();
    
    /**
     * Get native library configuration ini
     * @return Configuration ini
     */
    public static native String getConfigurationIni();
    
    /**
     * Get native library configuration toml
     * @return Configuration toml
     */
    public static native String getConfigurationToml();
    
    /**
     * Get native library configuration hocon
     * @return Configuration hocon
     */
    public static native String getConfigurationHocon();
    
    /**
     * Get native library configuration hjson
     * @return Configuration hjson
     */
    public static native String getConfigurationHjson();
    
    /**
     * Get native library configuration edn
     * @return Configuration edn
     */
    public static native String getConfigurationEdn();
    
    /**
     * Get native library configuration cson
     * @return Configuration cson
     */
    public static native String getConfigurationCson();
    
    /**
     * Get native library configuration yaml
     * @return Configuration yaml
     */
    public static native String getConfigurationYaml();
    
    /**
     * Get native library configuration json
     * @return Configuration json
     */
    public static native String getConfigurationJson();
    
    /**
     * Get native library configuration xml
     * @return Configuration xml
     */
    public static native String getConfigurationXml();
    
    /**
     * Get native library configuration properties
     * @return Configuration properties
     */
    public static native String getConfigurationProperties();
    
    /**
     * Get native library configuration ini
     * @return Configuration ini
     */
    public static native String getConfigurationIni();
    
    /**
     * Get native library configuration toml
     * @return Configuration toml
     */
    public static native String getConfigurationToml();
    
    /**
     * Get native library configuration hocon
     * @return Configuration hocon
     */
    public static native String getConfigurationHocon();
    
    /**
     * Get native library configuration hjson
     * @return Configuration hjson
     */
    public static native String getConfigurationHjson();
    
    /**
     * Get native library configuration edn
     * @return Configuration edn
     */
    public static native String getConfigurationEdn();
    
    /**
     * Get native library configuration cson
     * @return Configuration cson
     */
    public static native String getConfigurationCson();
} 