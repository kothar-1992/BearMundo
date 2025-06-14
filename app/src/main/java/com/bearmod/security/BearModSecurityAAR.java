package com.bearmod.security;

import android.content.Context;
import android.util.Log;
import org.json.JSONObject;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class BearModSecurityAAR {
    private static final String TAG = "BearModSecurityAAR";
    private static BearModSecurityAAR instance;
    private final Context context;
    private final ScheduledExecutorService executor;
    private boolean isInitialized;
    private String keyAuthToken;
    private SecurityEventListener listener;

    static {
        System.loadLibrary("bearmod_security");
    }

    public interface SecurityEventListener {
        void onSecurityStateChanged(JSONObject state);
        void onThreatDetected(String threatType, String details);
        void onOffsetUpdated(String name, long value);
        void onUpdateFailed(String error);
    }

    private BearModSecurityAAR(Context context) {
        this.context = context.getApplicationContext();
        this.executor = Executors.newSingleThreadScheduledExecutor();
        this.isInitialized = false;
    }

    public static synchronized BearModSecurityAAR getInstance(Context context) {
        if (instance == null) {
            instance = new BearModSecurityAAR(context);
        }
        return instance;
    }

    public void setListener(SecurityEventListener listener) {
        this.listener = listener;
    }

    public void initialize(String keyAuthToken) {
        if (isInitialized) return;

        this.keyAuthToken = keyAuthToken;
        
        // Initialize native security
        if (nativeInitialize()) {
            isInitialized = true;
            startSecurityMonitoring();
            enableKernelProtection();
        } else {
            Log.e(TAG, "Failed to initialize security");
        }
    }

    public void addGameOffset(String name, long value) {
        if (!isInitialized) return;
        
        if (nativeAddOffset(name, value)) {
            if (listener != null) {
                listener.onOffsetUpdated(name, value);
            }
        }
    }

    public long getGameOffset(String name) {
        if (!isInitialized) return 0;
        return nativeGetOffset(name);
    }

    public boolean updateGameOffset(String name, long value) {
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

    private void startSecurityMonitoring() {
        executor.scheduleAtFixedRate(() -> {
            if (!isInitialized) return;
            
            String stateJson = nativeGetSecurityState();
            try {
                JSONObject state = new JSONObject(stateJson);
                
                if (listener != null) {
                    listener.onSecurityStateChanged(state);
                    
                    // Check for specific threats
                    if (state.optBoolean("hook_detected", false)) {
                        listener.onThreatDetected("HOOK", "Code injection detected");
                    }
                    if (state.optBoolean("debugger_detected", false)) {
                        listener.onThreatDetected("DEBUGGER", "Debugger attached");
                    }
                    if (state.optBoolean("emulator_detected", false)) {
                        listener.onThreatDetected("EMULATOR", "Running in emulator");
                    }
                    if (state.optBoolean("root_detected", false)) {
                        listener.onThreatDetected("ROOT", "Device is rooted");
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Error processing security state", e);
            }
        }, 0, 100, TimeUnit.MILLISECONDS);
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
        
        nativeCleanup();
        isInitialized = false;
    }

    // Native methods
    private native boolean nativeInitialize();
    private native boolean nativeAddOffset(String name, long value);
    private native long nativeGetOffset(String name);
    private native boolean nativeUpdateOffset(String name, long value);
    private native void nativeEnableKernelProtection();
    private native void nativeDisableKernelProtection();
    private native boolean nativeIsKernelProtected();
    private native String nativeGetSecurityState();
    private native void nativeCleanup();
} 