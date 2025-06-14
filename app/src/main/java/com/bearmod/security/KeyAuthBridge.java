package com.bearmod.security;

import android.content.Context;

public class KeyAuthBridge {
    static {
        System.loadLibrary("bearmod_security");
    }
    
    private static KeyAuthBridge instance;
    private boolean isInitialized;
    
    private KeyAuthBridge() {
        isInitialized = false;
    }
    
    public static synchronized KeyAuthBridge getInstance() {
        if (instance == null) {
            instance = new KeyAuthBridge();
        }
        return instance;
    }
    
    public boolean initialize(Context context) {
        if (!isInitialized) {
            isInitialized = nativeInitialize(context);
        }
        return isInitialized;
    }
    
    public boolean authenticate(String licenseKey, Context context) {
        if (!isInitialized) {
            return false;
        }
        return nativeAuthenticate(licenseKey, context);
    }
    
    public boolean validateSession() {
        return nativeValidateSession();
    }
    
    public void logout() {
        nativeLogout();
    }
    
    public boolean isDeviceSecure() {
        return nativeIsDeviceSecure();
    }
    
    // Native methods
    private native boolean nativeInitialize(Context context);
    private native boolean nativeAuthenticate(String licenseKey, Context context);
    private native boolean nativeValidateSession();
    private native void nativeLogout();
    private native boolean nativeIsDeviceSecure();
} 