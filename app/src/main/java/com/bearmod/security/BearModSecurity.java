package com.bearmod.security;

import android.content.Context;
import android.util.Log;

/**
 * Main security interface for BearMod library
 * Handles authentication and security validation
 */
public class BearModSecurity {
    private static final String TAG = "BearModSecurity";
    private static BearModSecurity instance;
    private final KeyAuthBridge keyAuthBridge;
    private boolean isInitialized;

    private BearModSecurity() {
        this.keyAuthBridge = KeyAuthBridge.getInstance();
        this.isInitialized = false;
    }

    public static synchronized BearModSecurity getInstance() {
        if (instance == null) {
            instance = new BearModSecurity();
        }
        return instance;
    }

    /**
     * Initialize the security module
     * @param context Application context
     * @return true if initialization was successful
     */
    public boolean initialize(Context context) {
        if (isInitialized) return true;

        try {
            isInitialized = keyAuthBridge.initialize(context);
            if (isInitialized) {
                Log.i(TAG, "Security module initialized successfully");
            } else {
                Log.e(TAG, "Failed to initialize security module");
            }
        } catch (Exception e) {
            Log.e(TAG, "Error initializing security module", e);
            isInitialized = false;
        }

        return isInitialized;
    }

    /**
     * Authenticate with KeyAuth
     * @param licenseKey License key for authentication
     * @param context Application context
     * @return true if authentication was successful
     */
    public boolean authenticate(String licenseKey, Context context) {
        if (!isInitialized) {
            Log.e(TAG, "Security module not initialized");
            return false;
        }

        try {
            boolean result = keyAuthBridge.authenticate(licenseKey, context);
            if (result) {
                Log.i(TAG, "Authentication successful");
            } else {
                Log.e(TAG, "Authentication failed");
            }
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Error during authentication", e);
            return false;
        }
    }

    /**
     * Validate current session
     * @return true if session is valid
     */
    public boolean validateSession() {
        if (!isInitialized) {
            Log.e(TAG, "Security module not initialized");
            return false;
        }

        try {
            return keyAuthBridge.validateSession();
        } catch (Exception e) {
            Log.e(TAG, "Error validating session", e);
            return false;
        }
    }

    /**
     * Logout and clear session
     */
    public void logout() {
        if (!isInitialized) {
            Log.e(TAG, "Security module not initialized");
            return;
        }

        try {
            keyAuthBridge.logout();
            Log.i(TAG, "Logged out successfully");
        } catch (Exception e) {
            Log.e(TAG, "Error during logout", e);
        }
    }

    /**
     * Check if device is secure
     * @return true if device passes security checks
     */
    public boolean isDeviceSecure() {
        if (!isInitialized) {
            Log.e(TAG, "Security module not initialized");
            return false;
        }

        try {
            return keyAuthBridge.isDeviceSecure();
        } catch (Exception e) {
            Log.e(TAG, "Error checking device security", e);
            return false;
        }
    }
} 