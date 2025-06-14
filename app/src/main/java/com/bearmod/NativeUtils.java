package com.bearmod;

import android.content.Context;
import android.util.Log;

/**
 * Improved NativeUtils class for JNI communication
 */
public class NativeUtils {
    private static final String TAG = "NativeUtils";
    private static boolean sLibraryLoaded = false;

    // Load native library with proper error handling
    static {
        try {
            System.loadLibrary("bearmod");
            sLibraryLoaded = true;
            Log.d(TAG, "Native library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library", e);
            sLibraryLoaded = false;
        }
    }

    /**
     * Generic method to safely call native methods
     */
    private static <T> T safeNativeCall(NativeCall<T> call, T defaultValue) {
        if (!sLibraryLoaded) {
            Log.w(TAG, "Native library not loaded, returning default value");
            return defaultValue;
        }

        try {
            return call.execute();
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Native method not found", e);
            return defaultValue;
        } catch (Exception e) {
            Log.e(TAG, "Native call failed", e);
            return defaultValue;
        }
    }

    /**
     * Interface for native calls
     */
    private interface NativeCall<T> {
        T execute() throws Exception;
    }

    /**
     * Check if native library is loaded
     */
    public static boolean isLibraryLoaded() {
        return sLibraryLoaded;
    }

    /**
     * Legacy method for backward compatibility
     */
    public static boolean isNativeLibraryLoaded() {
        return isLibraryLoaded();
    }

    /**
     * Get version information
     */
    public static String getVersion() {
        return safeNativeCall(() -> nativeGetVersion(), "1.0.0");
    }

    /**
     * Initialize native code
     */
    public static boolean initialize(Context context) {
        if (context == null) return false;
        return safeNativeCall(() -> nativeInitialize(context), false);
    }

    /**
     * Clean up native resources
     */
    public static void cleanup() {
        if (!sLibraryLoaded) return;

        try {
            nativeCleanup();
        } catch (Exception e) {
            Log.e(TAG, "Error in cleanup", e);
        }
    }

    /**
     * Draw on ESP view
     */
    public static void drawOn(ESPView espView, android.graphics.Canvas canvas) {
        if (!sLibraryLoaded || espView == null || canvas == null) return;

        try {
            nativeDrawOn(espView, canvas);
        } catch (Exception e) {
            Log.e(TAG, "Error in drawOn", e);
        }
    }

    /**
     * Safe version of drawOn that handles exceptions
     */
    public static void safeDrawOn(ESPView espView, android.graphics.Canvas canvas) {
        if (!sLibraryLoaded || espView == null || canvas == null) return;

        try {
            nativeDrawOn(espView, canvas);
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Native method not found: " + e.getMessage());
        } catch (Exception e) {
            Log.e(TAG, "Error in safeDrawOn", e);
        }
    }

    /**
     * Check if ESP is hidden
     */
    public static boolean isEspHidden() {
        return safeNativeCall(() -> nativeIsEspHidden(), false);
    }

    /**
     * Send configuration to native code
     */
    public static void sendConfig(String config, String value) {
        if (!sLibraryLoaded || config == null || value == null) return;

        try {
            nativeSendConfig(config, value);
        } catch (Exception e) {
            Log.e(TAG, "Error sending config", e);
        }
    }

    /**
     * Check if game service is connected
     */
    public static boolean isGameServiceConnected() {
        return safeNativeCall(() -> nativeIsGameServiceConnected(), false);
    }

    /**
     * Check if game service is connected with retry
     * @param maxRetries Maximum number of retry attempts
     * @param delayMs Delay between retries in milliseconds
     * @return true if connected, false otherwise
     */
    public static boolean isGameServiceConnectedWithRetry(int maxRetries, long delayMs) {
        for (int i = 0; i < maxRetries; i++) {
            boolean connected = isGameServiceConnected();
            if (connected) {
                return true;
            }

            if (i < maxRetries - 1) {
                Log.d(TAG, "Game service connection attempt " + (i + 1) + " failed, retrying...");
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    Log.e(TAG, "Interrupted during connection retry", e);
                    return false;
                }
            }
        }

        Log.e(TAG, "Game service connection failed after " + maxRetries + " attempts");
        return false;
    }

    // Native method declarations - private to prevent direct access
    private static native String nativeGetVersion();
    private static native boolean nativeInitialize(Context context);
    private static native void nativeCleanup();
    private static native void nativeDrawOn(ESPView espView, android.graphics.Canvas canvas);
    private static native boolean nativeIsEspHidden();
    private static native void nativeSendConfig(String config, String value);
    private static native boolean nativeIsGameServiceConnected();
}
