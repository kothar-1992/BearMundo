package com.bearmod.core.utils;

import android.content.Context;
import android.util.Log;

import com.bearmod.core.constants.BearModConstants;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Configuration utility for BearMod library
 */
public final class BearModConfig {
    private static final String TAG = "BearModConfig";
    
    private static File configDir;
    private static File configFile;
    private static JSONObject config;
    private static boolean isInitialized = false;
    
    private BearModConfig() {
        // Prevent instantiation
    }
    
    /**
     * Initialize configuration
     * @param context Application context
     * @return true if successful, false otherwise
     */
    public static synchronized boolean initialize(Context context) {
        if (isInitialized) {
            return true;
        }
        
        try {
            // Create config directory
            configDir = new File(context.getFilesDir(), BearModConstants.CONFIG_DIR);
            if (!BearModUtils.createDirectory(configDir)) {
                Log.e(TAG, "Failed to create config directory");
                return false;
            }
            
            // Create config file
            configFile = new File(configDir, BearModConstants.CONFIG_FILE);
            config = new JSONObject();
            
            // Load existing config
            if (configFile.exists()) {
                loadConfig();
            }
            
            isInitialized = true;
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize config", e);
            return false;
        }
    }
    
    /**
     * Cleanup configuration
     */
    public static synchronized void cleanup() {
        if (!isInitialized) {
            return;
        }
        
        try {
            saveConfig();
        } catch (Exception e) {
            Log.e(TAG, "Error during config cleanup", e);
        } finally {
            config = null;
            configFile = null;
            configDir = null;
            isInitialized = false;
        }
    }
    
    /**
     * Set configuration value
     * @param key Configuration key
     * @param value Configuration value
     */
    public static void set(String key, Object value) {
        if (!isInitialized) {
            return;
        }
        
        try {
            config.put(key, value);
        } catch (JSONException e) {
            Log.e(TAG, "Error setting config value", e);
        }
    }
    
    /**
     * Get configuration value
     * @param key Configuration key
     * @return Configuration value or null if not found
     */
    public static Object get(String key) {
        if (!isInitialized) {
            return null;
        }
        
        try {
            return config.get(key);
        } catch (JSONException e) {
            Log.e(TAG, "Error getting config value", e);
            return null;
        }
    }
    
    /**
     * Get configuration value as string
     * @param key Configuration key
     * @return Configuration value as string or null if not found
     */
    public static String getString(String key) {
        if (!isInitialized) {
            return null;
        }
        
        try {
            return config.getString(key);
        } catch (JSONException e) {
            Log.e(TAG, "Error getting config string value", e);
            return null;
        }
    }
    
    /**
     * Get configuration value as boolean
     * @param key Configuration key
     * @return Configuration value as boolean or false if not found
     */
    public static boolean getBoolean(String key) {
        if (!isInitialized) {
            return false;
        }
        
        try {
            return config.getBoolean(key);
        } catch (JSONException e) {
            Log.e(TAG, "Error getting config boolean value", e);
            return false;
        }
    }
    
    /**
     * Get configuration value as integer
     * @param key Configuration key
     * @return Configuration value as integer or 0 if not found
     */
    public static int getInt(String key) {
        if (!isInitialized) {
            return 0;
        }
        
        try {
            return config.getInt(key);
        } catch (JSONException e) {
            Log.e(TAG, "Error getting config integer value", e);
            return 0;
        }
    }
    
    /**
     * Get configuration value as long
     * @param key Configuration key
     * @return Configuration value as long or 0 if not found
     */
    public static long getLong(String key) {
        if (!isInitialized) {
            return 0;
        }
        
        try {
            return config.getLong(key);
        } catch (JSONException e) {
            Log.e(TAG, "Error getting config long value", e);
            return 0;
        }
    }
    
    /**
     * Get configuration value as double
     * @param key Configuration key
     * @return Configuration value as double or 0.0 if not found
     */
    public static double getDouble(String key) {
        if (!isInitialized) {
            return 0.0;
        }
        
        try {
            return config.getDouble(key);
        } catch (JSONException e) {
            Log.e(TAG, "Error getting config double value", e);
            return 0.0;
        }
    }
    
    /**
     * Remove configuration value
     * @param key Configuration key
     */
    public static void remove(String key) {
        if (!isInitialized) {
            return;
        }
        
        config.remove(key);
    }
    
    /**
     * Clear configuration
     */
    public static void clear() {
        if (!isInitialized) {
            return;
        }
        
        config = new JSONObject();
    }
    
    /**
     * Check if configuration contains key
     * @param key Configuration key
     * @return true if configuration contains key, false otherwise
     */
    public static boolean contains(String key) {
        if (!isInitialized) {
            return false;
        }
        
        return config.has(key);
    }
    
    /**
     * Get all configuration values
     * @return Map of all configuration values
     */
    public static Map<String, Object> getAll() {
        if (!isInitialized) {
            return new HashMap<>();
        }
        
        Map<String, Object> result = new HashMap<>();
        Iterator<String> keys = config.keys();
        
        while (keys.hasNext()) {
            String key = keys.next();
            try {
                result.put(key, config.get(key));
            } catch (JSONException e) {
                Log.e(TAG, "Error getting config value", e);
            }
        }
        
        return result;
    }
    
    /**
     * Load configuration from file
     */
    private static void loadConfig() {
        try (FileInputStream fis = new FileInputStream(configFile)) {
            byte[] buffer = new byte[(int) configFile.length()];
            fis.read(buffer);
            String json = new String(buffer, StandardCharsets.UTF_8);
            config = new JSONObject(json);
        } catch (Exception e) {
            Log.e(TAG, "Error loading config", e);
        }
    }
    
    /**
     * Save configuration to file
     */
    private static void saveConfig() {
        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            String json = config.toString(2);
            fos.write(json.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | JSONException e) {
            Log.e(TAG, "Error saving config", e);
        }
    }
} 