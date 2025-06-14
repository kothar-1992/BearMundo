package com.bearmod.core.utils;

import android.content.Context;
import android.util.Log;

import com.bearmod.core.constants.BearModConstants;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cache utility for BearMod library
 */
public final class BearModCache {
    private static final String TAG = "BearModCache";
    
    private static File cacheDir;
    private static File cacheFile;
    private static Map<String, CacheEntry> cache;
    private static boolean isInitialized = false;
    
    private BearModCache() {
        // Prevent instantiation
    }
    
    /**
     * Initialize cache
     * @param context Application context
     * @return true if successful, false otherwise
     */
    public static synchronized boolean initialize(Context context) {
        if (isInitialized) {
            return true;
        }
        
        try {
            // Create cache directory
            cacheDir = new File(context.getFilesDir(), BearModConstants.CACHE_DIR);
            if (!BearModUtils.createDirectory(cacheDir)) {
                Log.e(TAG, "Failed to create cache directory");
                return false;
            }
            
            // Create cache file
            cacheFile = new File(cacheDir, BearModConstants.CACHE_FILE);
            cache = new ConcurrentHashMap<>();
            
            // Load existing cache
            if (cacheFile.exists()) {
                loadCache();
            }
            
            isInitialized = true;
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize cache", e);
            return false;
        }
    }
    
    /**
     * Cleanup cache
     */
    public static synchronized void cleanup() {
        if (!isInitialized) {
            return;
        }
        
        try {
            saveCache();
        } catch (Exception e) {
            Log.e(TAG, "Error during cache cleanup", e);
        } finally {
            cache = null;
            cacheFile = null;
            cacheDir = null;
            isInitialized = false;
        }
    }
    
    /**
     * Put value in cache
     * @param key Cache key
     * @param value Cache value
     * @param expiryTime Expiry time in milliseconds
     */
    public static void put(String key, Serializable value, long expiryTime) {
        if (!isInitialized) {
            return;
        }
        
        cache.put(key, new CacheEntry(value, System.currentTimeMillis() + expiryTime));
    }
    
    /**
     * Get value from cache
     * @param key Cache key
     * @return Cache value or null if not found or expired
     */
    public static Object get(String key) {
        if (!isInitialized) {
            return null;
        }
        
        CacheEntry entry = cache.get(key);
        if (entry == null) {
            return null;
        }
        
        if (entry.isExpired()) {
            cache.remove(key);
            return null;
        }
        
        return entry.getValue();
    }
    
    /**
     * Remove value from cache
     * @param key Cache key
     */
    public static void remove(String key) {
        if (!isInitialized) {
            return;
        }
        
        cache.remove(key);
    }
    
    /**
     * Clear cache
     */
    public static void clear() {
        if (!isInitialized) {
            return;
        }
        
        cache.clear();
    }
    
    /**
     * Check if cache contains key
     * @param key Cache key
     * @return true if cache contains key, false otherwise
     */
    public static boolean contains(String key) {
        if (!isInitialized) {
            return false;
        }
        
        CacheEntry entry = cache.get(key);
        if (entry == null) {
            return false;
        }
        
        if (entry.isExpired()) {
            cache.remove(key);
            return false;
        }
        
        return true;
    }
    
    /**
     * Get cache size
     * @return Cache size
     */
    public static int size() {
        if (!isInitialized) {
            return 0;
        }
        
        return cache.size();
    }
    
    /**
     * Load cache from file
     */
    private static void loadCache() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(cacheFile))) {
            @SuppressWarnings("unchecked")
            Map<String, CacheEntry> loadedCache = (Map<String, CacheEntry>) ois.readObject();
            
            // Remove expired entries
            loadedCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
            
            cache.putAll(loadedCache);
        } catch (Exception e) {
            Log.e(TAG, "Error loading cache", e);
        }
    }
    
    /**
     * Save cache to file
     */
    private static void saveCache() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(cacheFile))) {
            oos.writeObject(new HashMap<>(cache));
        } catch (IOException e) {
            Log.e(TAG, "Error saving cache", e);
        }
    }
    
    /**
     * Cache entry
     */
    private static class CacheEntry implements Serializable {
        private static final long serialVersionUID = 1L;
        
        private final Serializable value;
        private final long expiryTime;
        
        public CacheEntry(Serializable value, long expiryTime) {
            this.value = value;
            this.expiryTime = expiryTime;
        }
        
        public Serializable getValue() {
            return value;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }
} 