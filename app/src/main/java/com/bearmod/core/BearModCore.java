package com.bearmod.core;

import android.content.Context;
import android.util.Log;

import com.bearmod.core.hooks.HookManager;
import com.bearmod.core.utils.Logger;

/**
 * Core class for the Bear-Mod application
 * 
 * This class provides a singleton interface to the core functionality
 */
public class BearModCore {
    private static final String TAG = "BearModCore";
    private static BearModCore instance;
    
    private final Context context;
    private boolean initialized = false;
    
    /**
     * Private constructor to prevent direct instantiation
     * 
     * @param context Application context
     */
    private BearModCore(Context context) {
        this.context = context.getApplicationContext();
    }
    
    /**
     * Get the singleton instance
     * 
     * @param context Application context
     * @return Singleton instance
     */
    public static synchronized BearModCore getInstance(Context context) {
        if (instance == null) {
            instance = new BearModCore(context);
        }
        return instance;
    }
    
    /**
     * Initialize the core
     * 
     * @return true if initialization was successful, false otherwise
     */
    public boolean initialize() {
        if (initialized) {
            Log.i(TAG, "Core already initialized");
            return true;
        }
        
        Log.i(TAG, "Initializing core");
        
        // Initialize logger
        Logger.initialize(context);
        
        // Initialize native bridge
        boolean nativeInitialized = NativeBridge.initialize();
        if (!nativeInitialized) {
            Log.e(TAG, "Failed to initialize native bridge");
            return false;
        }
        
        // Initialize hook manager
        HookManager hookManager = HookManager.getInstance();
        boolean hookManagerInitialized = hookManager.initialize();
        if (!hookManagerInitialized) {
            Log.e(TAG, "Failed to initialize hook manager");
            return false;
        }
        
        initialized = true;
        Log.i(TAG, "Core initialized successfully");
        return true;
    }
    
    /**
     * Get the application context
     * 
     * @return Application context
     */
    public Context getContext() {
        return context;
    }
    
    /**
     * Get the hook manager
     * 
     * @return Hook manager instance
     */
    public HookManager getHookManager() {
        return HookManager.getInstance();
    }
    
    /**
     * Check if the core is initialized
     * 
     * @return true if the core is initialized, false otherwise
     */
    public boolean isInitialized() {
        return initialized;
    }
}
