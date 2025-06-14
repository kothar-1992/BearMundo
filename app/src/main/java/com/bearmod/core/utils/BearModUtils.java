package com.bearmod.core.utils;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import com.bearmod.core.constants.BearModConstants;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;

/**
 * Utility class for common operations in BearMod library
 */
public final class BearModUtils {
    private static final String TAG = "BearModUtils";
    
    private BearModUtils() {
        // Prevent instantiation
    }
    
    /**
     * Generate a unique container ID
     * @return Unique container ID
     */
    public static String generateContainerId() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * Calculate SHA-256 hash of a file
     * @param file File to hash
     * @return SHA-256 hash as hex string
     */
    public static String calculateFileHash(File file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(file);
            byte[] byteArray = new byte[1024];
            int bytesCount;
            
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
            
            fis.close();
            byte[] bytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            
            return sb.toString();
        } catch (NoSuchAlgorithmException | IOException e) {
            Log.e(TAG, "Error calculating file hash", e);
            return null;
        }
    }
    
    /**
     * Copy a file
     * @param sourceFile Source file
     * @param destFile Destination file
     * @return true if successful, false otherwise
     */
    public static boolean copyFile(File sourceFile, File destFile) {
        if (!sourceFile.exists()) {
            return false;
        }
        
        try {
            if (!destFile.exists()) {
                destFile.createNewFile();
            }
            
            FileChannel source = null;
            FileChannel destination = null;
            
            try {
                source = new FileInputStream(sourceFile).getChannel();
                destination = new FileOutputStream(destFile).getChannel();
                destination.transferFrom(source, 0, source.size());
                return true;
            } finally {
                if (source != null) {
                    source.close();
                }
                if (destination != null) {
                    destination.close();
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error copying file", e);
            return false;
        }
    }
    
    /**
     * Create directory if it doesn't exist
     * @param dir Directory to create
     * @return true if successful, false otherwise
     */
    public static boolean createDirectory(File dir) {
        if (!dir.exists()) {
            return dir.mkdirs();
        }
        return true;
    }
    
    /**
     * Delete directory and its contents
     * @param dir Directory to delete
     * @return true if successful, false otherwise
     */
    public static boolean deleteDirectory(File dir) {
        if (dir.exists()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectory(file);
                    } else {
                        file.delete();
                    }
                }
            }
        }
        return dir.delete();
    }
    
    /**
     * Get application version name
     * @param context Application context
     * @return Version name
     */
    public static String getAppVersionName(Context context) {
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return pInfo.versionName;
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Error getting app version", e);
            return "unknown";
        }
    }
    
    /**
     * Get application version code
     * @param context Application context
     * @return Version code
     */
    public static int getAppVersionCode(Context context) {
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return pInfo.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Error getting app version code", e);
            return -1;
        }
    }
    
    /**
     * Check if device is rooted
     * @return true if device is rooted, false otherwise
     */
    public static boolean isDeviceRooted() {
        String[] rootPaths = {
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
        
        return Arrays.stream(rootPaths).anyMatch(path -> new File(path).exists());
    }
    
    /**
     * Check if device is an emulator
     * @return true if device is an emulator, false otherwise
     */
    public static boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
            || Build.FINGERPRINT.startsWith("unknown")
            || Build.MODEL.contains("google_sdk")
            || Build.MODEL.contains("Emulator")
            || Build.MODEL.contains("Android SDK built for x86")
            || Build.MANUFACTURER.contains("Genymotion")
            || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
            || "google_sdk".equals(Build.PRODUCT);
    }
    
    /**
     * Check if app is running in debug mode
     * @param context Application context
     * @return true if app is in debug mode, false otherwise
     */
    public static boolean isDebugMode(Context context) {
        return (context.getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }
    
    /**
     * Get device information
     * @return Device information string
     */
    public static String getDeviceInfo() {
        return String.format("Device: %s\nModel: %s\nManufacturer: %s\nAndroid Version: %s\nSDK: %d",
            Build.DEVICE,
            Build.MODEL,
            Build.MANUFACTURER,
            Build.VERSION.RELEASE,
            Build.VERSION.SDK_INT);
    }
    
    /**
     * Validate container name
     * @param name Container name to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidContainerName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        
        // Check length
        if (name.length() > 64) {
            return false;
        }
        
        // Check for invalid characters
        return name.matches("^[a-zA-Z0-9_-]+$");
    }
    
    /**
     * Validate password
     * @param password Password to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidPassword(String password) {
        if (password == null) {
            return false;
        }
        
        int length = password.length();
        if (length < BearModConstants.MIN_PASSWORD_LENGTH || length > BearModConstants.MAX_PASSWORD_LENGTH) {
            return false;
        }
        
        // Check for at least one uppercase letter
        if (!password.matches(".*[A-Z].*")) {
            return false;
        }
        
        // Check for at least one lowercase letter
        if (!password.matches(".*[a-z].*")) {
            return false;
        }
        
        // Check for at least one number
        if (!password.matches(".*\\d.*")) {
            return false;
        }
        
        // Check for at least one special character
        if (!password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) {
            return false;
        }
        
        return true;
    }
} 