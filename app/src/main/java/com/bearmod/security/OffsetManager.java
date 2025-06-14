package com.bearmod.security;

import android.util.Log;
import org.json.JSONObject;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class OffsetManager {
    private static final String TAG = "OffsetManager";
    private static OffsetManager instance;
    private final ScheduledExecutorService executor;
    private boolean isInitialized;
    private String keyAuthToken;
    private String serverUrl;
    private OffsetUpdateListener listener;

    static {
        System.loadLibrary("offset_container");
    }

    public interface OffsetUpdateListener {
        void onOffsetUpdated(String name, long value);
        void onUpdateFailed(String error);
    }

    private OffsetManager() {
        executor = Executors.newSingleThreadScheduledExecutor();
        isInitialized = false;
    }

    public static synchronized OffsetManager getInstance() {
        if (instance == null) {
            instance = new OffsetManager();
        }
        return instance;
    }

    public void setListener(OffsetUpdateListener listener) {
        this.listener = listener;
    }

    public void initialize(String keyAuthToken, String serverUrl) {
        if (isInitialized) return;

        this.keyAuthToken = keyAuthToken;
        this.serverUrl = serverUrl;
        
        // Initialize native container
        byte[] key = generateEncryptionKey();
        if (nativeInitialize(key)) {
            isInitialized = true;
            startPeriodicUpdates();
        } else {
            Log.e(TAG, "Failed to initialize offset container");
        }
    }

    public void addOffset(String name, long value) {
        if (!isInitialized) return;
        
        if (nativeAddOffset(name, value)) {
            if (listener != null) {
                listener.onOffsetUpdated(name, value);
            }
        }
    }

    public long getOffset(String name) {
        if (!isInitialized) return 0;
        return nativeGetOffset(name);
    }

    public boolean updateOffset(String name, long value) {
        if (!isInitialized) return false;
        
        if (nativeUpdateOffset(name, value)) {
            if (listener != null) {
                listener.onOffsetUpdated(name, value);
            }
            return true;
        }
        return false;
    }

    public void enableKernelProtection() {
        if (!isInitialized) return;
        nativeEnableKernelProtection();
    }

    public void disableKernelProtection() {
        if (!isInitialized) return;
        nativeDisableKernelProtection();
    }

    public boolean isKernelProtected() {
        if (!isInitialized) return false;
        return nativeIsKernelProtected();
    }

    private void startPeriodicUpdates() {
        executor.scheduleAtFixedRate(() -> {
            if (!isInitialized) return;
            
            if (nativeUpdateFromServer(serverUrl, keyAuthToken)) {
                Log.d(TAG, "Successfully updated offsets from server");
            } else {
                Log.e(TAG, "Failed to update offsets from server");
                if (listener != null) {
                    listener.onUpdateFailed("Failed to update offsets from server");
                }
            }
        }, 0, 5, TimeUnit.MINUTES);
    }

    private byte[] generateEncryptionKey() {
        byte[] key = new byte[32];
        // Use KeyAuth's secure random generator
        KeyAuthIntegrator.getInstance().getSecureRandom().nextBytes(key);
        return key;
    }

    public void shutdown() {
        if (!isInitialized) return;
        
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        nativeClear();
        isInitialized = false;
    }

    // Native methods
    private native boolean nativeInitialize(byte[] key);
    private native boolean nativeAddOffset(String name, long value);
    private native long nativeGetOffset(String name);
    private native boolean nativeUpdateOffset(String name, long value);
    private native void nativeEnableKernelProtection();
    private native void nativeDisableKernelProtection();
    private native boolean nativeIsKernelProtected();
    private native boolean nativeUpdateFromServer(String serverUrl, String authToken);
    private native void nativeClear();
} 