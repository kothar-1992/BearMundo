package com.bearmod.core.hooks;

import android.util.Log;

import com.bearmod.core.NativeBridge;

import java.util.HashMap;
import java.util.Map;

/**
 * Manager class for hooking functions
 * 
 * This class provides a Java interface to the native hooking functionality
 */
public class HookManager {
    private static final String TAG = "HookManager";
    private static HookManager instance;
    
    private boolean initialized = false;
    private final Map<String, HookInfo> activeHooks = new HashMap<>();
    
    /**
     * Private constructor to prevent direct instantiation
     */
    private HookManager() {
    }
    
    /**
     * Get the singleton instance
     * 
     * @return Singleton instance
     */
    public static synchronized HookManager getInstance() {
        if (instance == null) {
            instance = new HookManager();
        }
        return instance;
    }
    
    /**
     * Initialize the hook manager
     * 
     * @return true if initialization was successful, false otherwise
     */
    public boolean initialize() {
        if (initialized) {
            Log.i(TAG, "Hook manager already initialized");
            return true;
        }
        
        Log.i(TAG, "Initializing hook manager");
        
        // Initialization logic here
        
        initialized = true;
        Log.i(TAG, "Hook manager initialized successfully");
        return true;
    }
    
    /**
     * Hook a method
     * 
     * @param libraryName Name of the library containing the function
     * @param functionName Name of the function to hook
     * @param hookType Type of hook to apply
     * @return true if hooking was successful, false otherwise
     */
    public boolean hookFunction(String libraryName, String functionName, HookType hookType) {
        if (!initialized) {
            Log.e(TAG, "Hook manager not initialized");
            return false;
        }
        
        String hookId = libraryName + ":" + functionName;
        if (activeHooks.containsKey(hookId)) {
            Log.w(TAG, "Function already hooked: " + hookId);
            return true;
        }
        
        Log.i(TAG, "Hooking function: " + hookId);
        
        boolean success = NativeBridge.hookFunction(libraryName, functionName, hookType.ordinal());
        if (success) {
            activeHooks.put(hookId, new HookInfo(libraryName, functionName, hookType));
            Log.i(TAG, "Function hooked successfully: " + hookId);
        } else {
            Log.e(TAG, "Failed to hook function: " + hookId);
        }
        
        return success;
    }
    
    /**
     * Check if a function is hooked
     * 
     * @param libraryName Name of the library containing the function
     * @param functionName Name of the function
     * @return true if the function is hooked, false otherwise
     */
    public boolean isFunctionHooked(String libraryName, String functionName) {
        String hookId = libraryName + ":" + functionName;
        return activeHooks.containsKey(hookId);
    }
    
    /**
     * Get information about an active hook
     * 
     * @param libraryName Name of the library containing the function
     * @param functionName Name of the function
     * @return Hook information, or null if the function is not hooked
     */
    public HookInfo getHookInfo(String libraryName, String functionName) {
        String hookId = libraryName + ":" + functionName;
        return activeHooks.get(hookId);
    }
    
    /**
     * Get all active hooks
     * 
     * @return Map of hook IDs to hook information
     */
    public Map<String, HookInfo> getActiveHooks() {
        return new HashMap<>(activeHooks);
    }
    
    /**
     * Check if the hook manager is initialized
     * 
     * @return true if the hook manager is initialized, false otherwise
     */
    public boolean isInitialized() {
        return initialized;
    }
}
