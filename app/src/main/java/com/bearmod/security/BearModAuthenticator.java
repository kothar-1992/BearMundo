package com.bearmod.security;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class BearModAuthenticator {
    private static final String TAG = "BearModAuthenticator";
    private static BearModAuthenticator instance;
    private final Context context;

    private BearModAuthenticator(Context context) {
        this.context = context.getApplicationContext();
    }

    public static synchronized BearModAuthenticator getInstance(Context context) {
        if (instance == null) {
            instance = new BearModAuthenticator(context);
        }
        return instance;
    }

    public boolean verifySignature(String expectedHash) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                context.getPackageName(),
                PackageManager.GET_SIGNATURES
            );

            for (Signature signature : packageInfo.signatures) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signature.toByteArray());
                String hash = bytesToHex(md.digest());
                
                if (hash.equalsIgnoreCase(expectedHash)) {
                    Log.d(TAG, "Signature verification successful");
                    return true;
                }
            }
            
            Log.e(TAG, "Signature verification failed");
            return false;
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Error during signature verification", e);
            return false;
        }
    }

    public void secureHostAllowed() {
        // Check if running in a secure environment
        if (isEmulator() || isRooted() || isDebuggerConnected()) {
            throw new SecurityException("Insecure environment detected");
        }
    }

    private boolean isEmulator() {
        return android.os.Build.FINGERPRINT.startsWith("generic")
            || android.os.Build.FINGERPRINT.startsWith("unknown")
            || android.os.Build.MODEL.contains("google_sdk")
            || android.os.Build.MODEL.contains("Emulator")
            || android.os.Build.MODEL.contains("Android SDK built for x86")
            || android.os.Build.MANUFACTURER.contains("Genymotion")
            || (android.os.Build.BRAND.startsWith("generic") && android.os.Build.DEVICE.startsWith("generic"))
            || "google_sdk".equals(android.os.Build.PRODUCT);
    }

    private boolean isRooted() {
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        };
        
        for (String path : paths) {
            if (new java.io.File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean isDebuggerConnected() {
        return android.os.Debug.isDebuggerConnected();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
} 