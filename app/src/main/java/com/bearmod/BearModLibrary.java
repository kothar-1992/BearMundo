package com.bearmod;

import android.content.Context;
import android.util.Log;

import com.bearmod.core.BearModCore;
import com.bearmod.core.auth.BearModAuthenticationManager;
import com.bearmod.core.container.BearModContainerManager;
import com.bearmod.core.config.BearModConfiguration;
import com.bearmod.core.security.BearModSecurityManager;

/**
 * Main entry point for the BearMod AAR library
 * Provides a simple interface for host applications to integrate BearMod functionality
 */
public class BearModLibrary {
    private static final String TAG = "BearModLibrary";
    private static BearModLibrary instance;
    
    private final Context context;
    private boolean initialized = false;
    private BearModConfiguration configuration;
    
    /**
     * Private constructor to prevent direct instantiation
     */
    private BearModLibrary(Context context) {
        this.context = context.getApplicationContext();
    }
    
    /**
     * Get the singleton instance
     */
    public static synchronized BearModLibrary getInstance(Context context) {
        if (instance == null) {
            instance = new BearModLibrary(context);
        }
        return instance;
    }
    
    /**
     * Initialize the library with default configuration
     */
    public boolean initialize() {
        return initialize(BearModConfiguration.builder().build());
    }
    
    /**
     * Initialize the library with custom configuration
     */
    public boolean initialize(BearModConfiguration config) {
        if (initialized) {
            Log.i(TAG, "Library already initialized");
            return true;
        }
        
        Log.i(TAG, "Initializing BearMod Library");
        
        try {
            // Store configuration
            this.configuration = config;
            
            // Initialize core components
            if (!BearModCore.getInstance(context).initialize()) {
                Log.e(TAG, "Failed to initialize core");
                return false;
            }
            
            // Initialize security manager
            if (!BearModSecurityManager.getInstance().initialize(context, config)) {
                Log.e(TAG, "Failed to initialize security manager");
                return false;
            }
            
            // Initialize authentication manager
            if (!BearModAuthenticationManager.getInstance().initialize(context, config)) {
                Log.e(TAG, "Failed to initialize authentication manager");
                return false;
            }
            
            // Initialize container manager
            if (!BearModContainerManager.getInstance().initialize(context, config)) {
                Log.e(TAG, "Failed to initialize container manager");
                return false;
            }
            
            initialized = true;
            Log.i(TAG, "Library initialized successfully");
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "Error initializing library", e);
            return false;
        }
    }
    
    /**
     * Get the core instance
     */
    public BearModCore getCore() {
        ensureInitialized();
        return BearModCore.getInstance(context);
    }
    
    /**
     * Get the security manager
     */
    public BearModSecurityManager getSecurityManager() {
        ensureInitialized();
        return BearModSecurityManager.getInstance();
    }
    
    /**
     * Get the authentication manager
     */
    public BearModAuthenticationManager getAuthManager() {
        ensureInitialized();
        return BearModAuthenticationManager.getInstance();
    }
    
    /**
     * Get the container manager
     */
    public BearModContainerManager getContainerManager() {
        ensureInitialized();
        return BearModContainerManager.getInstance();
    }
    
    /**
     * Get the current configuration
     */
    public BearModConfiguration getConfiguration() {
        ensureInitialized();
        return configuration;
    }
    
    /**
     * Check if the library is initialized
     */
    public boolean isInitialized() {
        return initialized;
    }
    
    /**
     * Cleanup library resources
     */
    public void cleanup() {
        if (!initialized) {
            return;
        }
        
        Log.i(TAG, "Cleaning up library resources");
        
        try {
            // Cleanup core
            BearModCore.getInstance(context).cleanup();
            
            // Cleanup security manager
            BearModSecurityManager.getInstance().cleanup();
            
            // Cleanup authentication manager
            BearModAuthenticationManager.getInstance().cleanup();
            
            // Cleanup container manager
            BearModContainerManager.getInstance().cleanupAll();
            
            initialized = false;
            Log.i(TAG, "Library cleanup completed");
            
        } catch (Exception e) {
            Log.e(TAG, "Error during library cleanup", e);
        }
    }
    
    /**
     * Ensure library is initialized
     */
    private void ensureInitialized() {
        if (!initialized) {
            throw new IllegalStateException("Library not initialized. Call initialize() first.");
        }
    }
} 