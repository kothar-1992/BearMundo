package com.bearmod.core.utils;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Security utility for BearMod library
 */
public final class BearModSecurity {
    private static final String TAG = "BearModSecurity";
    
    private BearModSecurity() {
        // Prevent instantiation
    }
    
    /**
     * Check if app is running in debug mode
     * @param context Application context
     * @return true if app is in debug mode, false otherwise
     */
    public static boolean isDebugMode(Context context) {
        return BearModUtils.isDebugMode(context);
    }
    
    /**
     * Check if device is rooted
     * @return true if device is rooted, false otherwise
     */
    public static boolean isDeviceRooted() {
        return BearModUtils.isDeviceRooted();
    }
    
    /**
     * Check if device is an emulator
     * @return true if device is an emulator, false otherwise
     */
    public static boolean isEmulator() {
        return BearModUtils.isEmulator();
    }
    
    /**
     * Check if app is signed with debug key
     * @param context Application context
     * @return true if app is signed with debug key, false otherwise
     */
    public static boolean isDebugSigned(Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                context.getPackageName(), PackageManager.GET_SIGNATURES);
            
            for (Signature signature : packageInfo.signatures) {
                String signatureString = signature.toCharsString();
                if (signatureString.contains("Android Debug")) {
                    return true;
                }
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Error checking debug signature", e);
        }
        
        return false;
    }
    
    /**
     * Check if app is running in test environment
     * @param context Application context
     * @return true if app is running in test environment, false otherwise
     */
    public static boolean isTestEnvironment(Context context) {
        return isDebugMode(context) || isDebugSigned(context) || isEmulator();
    }
    
    /**
     * Check if app is running in production environment
     * @param context Application context
     * @return true if app is running in production environment, false otherwise
     */
    public static boolean isProductionEnvironment(Context context) {
        return !isTestEnvironment(context);
    }
    
    /**
     * Check if app is running in development environment
     * @param context Application context
     * @return true if app is running in development environment, false otherwise
     */
    public static boolean isDevelopmentEnvironment(Context context) {
        return isDebugMode(context) || isDebugSigned(context);
    }
    
    /**
     * Check if app is running in staging environment
     * @param context Application context
     * @return true if app is running in staging environment, false otherwise
     */
    public static boolean isStagingEnvironment(Context context) {
        return isEmulator() && !isDevelopmentEnvironment(context);
    }
    
    /**
     * Check if app is running in release build
     * @param context Application context
     * @return true if app is running in release build, false otherwise
     */
    public static boolean isReleaseBuild(Context context) {
        return !isDebugMode(context) && !isDebugSigned(context);
    }
    
    /**
     * Check if app is running in debug build
     * @param context Application context
     * @return true if app is running in debug build, false otherwise
     */
    public static boolean isDebugBuild(Context context) {
        return isDebugMode(context) || isDebugSigned(context);
    }
    
    /**
     * Check if app is running in release mode
     * @param context Application context
     * @return true if app is running in release mode, false otherwise
     */
    public static boolean isReleaseMode(Context context) {
        return isReleaseBuild(context) && !isEmulator();
    }
    
    /**
     * Check if app is running in debug mode
     * @param context Application context
     * @return true if app is running in debug mode, false otherwise
     */
    public static boolean isDebugMode(Context context) {
        return isDebugBuild(context) || isEmulator();
    }
    
    /**
     * Check if app is running in test mode
     * @param context Application context
     * @return true if app is running in test mode, false otherwise
     */
    public static boolean isTestMode(Context context) {
        return isTestEnvironment(context);
    }
    
    /**
     * Check if app is running in production mode
     * @param context Application context
     * @return true if app is running in production mode, false otherwise
     */
    public static boolean isProductionMode(Context context) {
        return isProductionEnvironment(context);
    }
    
    /**
     * Check if app is running in development mode
     * @param context Application context
     * @return true if app is running in development mode, false otherwise
     */
    public static boolean isDevelopmentMode(Context context) {
        return isDevelopmentEnvironment(context);
    }
    
    /**
     * Check if app is running in staging mode
     * @param context Application context
     * @return true if app is running in staging mode, false otherwise
     */
    public static boolean isStagingMode(Context context) {
        return isStagingEnvironment(context);
    }
    
    /**
     * Check if app is running in release environment
     * @param context Application context
     * @return true if app is running in release environment, false otherwise
     */
    public static boolean isReleaseEnvironment(Context context) {
        return isReleaseMode(context);
    }
    
    /**
     * Check if app is running in debug environment
     * @param context Application context
     * @return true if app is running in debug environment, false otherwise
     */
    public static boolean isDebugEnvironment(Context context) {
        return isDebugMode(context);
    }
    
    /**
     * Check if app is running in test build
     * @param context Application context
     * @return true if app is running in test build, false otherwise
     */
    public static boolean isTestBuild(Context context) {
        return isTestEnvironment(context);
    }
    
    /**
     * Check if app is running in production build
     * @param context Application context
     * @return true if app is running in production build, false otherwise
     */
    public static boolean isProductionBuild(Context context) {
        return isProductionEnvironment(context);
    }
    
    /**
     * Check if app is running in development build
     * @param context Application context
     * @return true if app is running in development build, false otherwise
     */
    public static boolean isDevelopmentBuild(Context context) {
        return isDevelopmentEnvironment(context);
    }
    
    /**
     * Check if app is running in staging build
     * @param context Application context
     * @return true if app is running in staging build, false otherwise
     */
    public static boolean isStagingBuild(Context context) {
        return isStagingEnvironment(context);
    }
    
    /**
     * Check if app is running in release environment
     * @param context Application context
     * @return true if app is running in release environment, false otherwise
     */
    public static boolean isReleaseEnvironment(Context context) {
        return isReleaseMode(context);
    }
    
    /**
     * Check if app is running in debug environment
     * @param context Application context
     * @return true if app is running in debug environment, false otherwise
     */
    public static boolean isDebugEnvironment(Context context) {
        return isDebugMode(context);
    }
    
    /**
     * Check if app is running in test environment
     * @param context Application context
     * @return true if app is running in test environment, false otherwise
     */
    public static boolean isTestEnvironment(Context context) {
        return isTestMode(context);
    }
    
    /**
     * Check if app is running in production environment
     * @param context Application context
     * @return true if app is running in production environment, false otherwise
     */
    public static boolean isProductionEnvironment(Context context) {
        return isProductionMode(context);
    }
    
    /**
     * Check if app is running in development environment
     * @param context Application context
     * @return true if app is running in development environment, false otherwise
     */
    public static boolean isDevelopmentEnvironment(Context context) {
        return isDevelopmentMode(context);
    }
    
    /**
     * Check if app is running in staging environment
     * @param context Application context
     * @return true if app is running in staging environment, false otherwise
     */
    public static boolean isStagingEnvironment(Context context) {
        return isStagingMode(context);
    }
    
    /**
     * Check if app is running in release mode
     * @param context Application context
     * @return true if app is running in release mode, false otherwise
     */
    public static boolean isReleaseMode(Context context) {
        return isReleaseEnvironment(context);
    }
    
    /**
     * Check if app is running in debug mode
     * @param context Application context
     * @return true if app is running in debug mode, false otherwise
     */
    public static boolean isDebugMode(Context context) {
        return isDebugEnvironment(context);
    }
    
    /**
     * Check if app is running in test mode
     * @param context Application context
     * @return true if app is running in test mode, false otherwise
     */
    public static boolean isTestMode(Context context) {
        return isTestEnvironment(context);
    }
    
    /**
     * Check if app is running in production mode
     * @param context Application context
     * @return true if app is running in production mode, false otherwise
     */
    public static boolean isProductionMode(Context context) {
        return isProductionEnvironment(context);
    }
    
    /**
     * Check if app is running in development mode
     * @param context Application context
     * @return true if app is running in development mode, false otherwise
     */
    public static boolean isDevelopmentMode(Context context) {
        return isDevelopmentEnvironment(context);
    }
    
    /**
     * Check if app is running in staging mode
     * @param context Application context
     * @return true if app is running in staging mode, false otherwise
     */
    public static boolean isStagingMode(Context context) {
        return isStagingEnvironment(context);
    }
    
    /**
     * Check if app is running in release build
     * @param context Application context
     * @return true if app is running in release build, false otherwise
     */
    public static boolean isReleaseBuild(Context context) {
        return isReleaseEnvironment(context);
    }
    
    /**
     * Check if app is running in debug build
     * @param context Application context
     * @return true if app is running in debug build, false otherwise
     */
    public static boolean isDebugBuild(Context context) {
        return isDebugEnvironment(context);
    }
    
    /**
     * Check if app is running in test build
     * @param context Application context
     * @return true if app is running in test build, false otherwise
     */
    public static boolean isTestBuild(Context context) {
        return isTestEnvironment(context);
    }
    
    /**
     * Check if app is running in production build
     * @param context Application context
     * @return true if app is running in production build, false otherwise
     */
    public static boolean isProductionBuild(Context context) {
        return isProductionEnvironment(context);
    }
    
    /**
     * Check if app is running in development build
     * @param context Application context
     * @return true if app is running in development build, false otherwise
     */
    public static boolean isDevelopmentBuild(Context context) {
        return isDevelopmentEnvironment(context);
    }
    
    /**
     * Check if app is running in staging build
     * @param context Application context
     * @return true if app is running in staging build, false otherwise
     */
    public static boolean isStagingBuild(Context context) {
        return isStagingEnvironment(context);
    }
} 