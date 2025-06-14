package com.bearmod.core.utils;

import android.content.Context;
import android.util.Log;

import com.bearmod.core.constants.BearModConstants;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;

/**
 * Container utility for BearMod library
 */
public final class BearModContainer {
    private static final String TAG = "BearModContainer";
    
    private BearModContainer() {
        // Prevent instantiation
    }
    
    /**
     * Create container
     * @param context Application context
     * @param name Container name
     * @return Container file or null if failed
     */
    public static File createContainer(Context context, String name) {
        if (!BearModUtils.isValidContainerName(name)) {
            Log.e(TAG, "Invalid container name: " + name);
            return null;
        }
        
        try {
            // Create container directory
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            if (!BearModUtils.createDirectory(containerDir)) {
                Log.e(TAG, "Failed to create container directory");
                return null;
            }
            
            // Create container file
            File containerFile = new File(containerDir, name + BearModConstants.CONTAINER_EXTENSION);
            if (containerFile.exists()) {
                Log.e(TAG, "Container already exists: " + name);
                return null;
            }
            
            if (!containerFile.createNewFile()) {
                Log.e(TAG, "Failed to create container file");
                return null;
            }
            
            return containerFile;
        } catch (IOException e) {
            Log.e(TAG, "Error creating container", e);
            return null;
        }
    }
    
    /**
     * Delete container
     * @param context Application context
     * @param name Container name
     * @return true if successful, false otherwise
     */
    public static boolean deleteContainer(Context context, String name) {
        if (!BearModUtils.isValidContainerName(name)) {
            Log.e(TAG, "Invalid container name: " + name);
            return false;
        }
        
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            File containerFile = new File(containerDir, name + BearModConstants.CONTAINER_EXTENSION);
            
            if (!containerFile.exists()) {
                Log.e(TAG, "Container does not exist: " + name);
                return false;
            }
            
            return containerFile.delete();
        } catch (Exception e) {
            Log.e(TAG, "Error deleting container", e);
            return false;
        }
    }
    
    /**
     * Get container
     * @param context Application context
     * @param name Container name
     * @return Container file or null if not found
     */
    public static File getContainer(Context context, String name) {
        if (!BearModUtils.isValidContainerName(name)) {
            Log.e(TAG, "Invalid container name: " + name);
            return null;
        }
        
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            File containerFile = new File(containerDir, name + BearModConstants.CONTAINER_EXTENSION);
            
            if (!containerFile.exists()) {
                Log.e(TAG, "Container does not exist: " + name);
                return null;
            }
            
            return containerFile;
        } catch (Exception e) {
            Log.e(TAG, "Error getting container", e);
            return null;
        }
    }
    
    /**
     * List containers
     * @param context Application context
     * @return List of container names
     */
    public static List<String> listContainers(Context context) {
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            if (!containerDir.exists()) {
                return new ArrayList<>();
            }
            
            File[] files = containerDir.listFiles((dir, name) -> name.endsWith(BearModConstants.CONTAINER_EXTENSION));
            if (files == null) {
                return new ArrayList<>();
            }
            
            List<String> containers = new ArrayList<>();
            for (File file : files) {
                String name = file.getName();
                name = name.substring(0, name.length() - BearModConstants.CONTAINER_EXTENSION.length());
                containers.add(name);
            }
            
            return containers;
        } catch (Exception e) {
            Log.e(TAG, "Error listing containers", e);
            return new ArrayList<>();
        }
    }
    
    /**
     * Copy container
     * @param context Application context
     * @param sourceName Source container name
     * @param destName Destination container name
     * @return true if successful, false otherwise
     */
    public static boolean copyContainer(Context context, String sourceName, String destName) {
        if (!BearModUtils.isValidContainerName(sourceName) || !BearModUtils.isValidContainerName(destName)) {
            Log.e(TAG, "Invalid container name");
            return false;
        }
        
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            File sourceFile = new File(containerDir, sourceName + BearModConstants.CONTAINER_EXTENSION);
            File destFile = new File(containerDir, destName + BearModConstants.CONTAINER_EXTENSION);
            
            if (!sourceFile.exists()) {
                Log.e(TAG, "Source container does not exist: " + sourceName);
                return false;
            }
            
            if (destFile.exists()) {
                Log.e(TAG, "Destination container already exists: " + destName);
                return false;
            }
            
            return BearModUtils.copyFile(sourceFile, destFile);
        } catch (Exception e) {
            Log.e(TAG, "Error copying container", e);
            return false;
        }
    }
    
    /**
     * Move container
     * @param context Application context
     * @param sourceName Source container name
     * @param destName Destination container name
     * @return true if successful, false otherwise
     */
    public static boolean moveContainer(Context context, String sourceName, String destName) {
        if (!BearModUtils.isValidContainerName(sourceName) || !BearModUtils.isValidContainerName(destName)) {
            Log.e(TAG, "Invalid container name");
            return false;
        }
        
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            File sourceFile = new File(containerDir, sourceName + BearModConstants.CONTAINER_EXTENSION);
            File destFile = new File(containerDir, destName + BearModConstants.CONTAINER_EXTENSION);
            
            if (!sourceFile.exists()) {
                Log.e(TAG, "Source container does not exist: " + sourceName);
                return false;
            }
            
            if (destFile.exists()) {
                Log.e(TAG, "Destination container already exists: " + destName);
                return false;
            }
            
            return sourceFile.renameTo(destFile);
        } catch (Exception e) {
            Log.e(TAG, "Error moving container", e);
            return false;
        }
    }
    
    /**
     * Get container size
     * @param context Application context
     * @param name Container name
     * @return Container size in bytes or -1 if not found
     */
    public static long getContainerSize(Context context, String name) {
        if (!BearModUtils.isValidContainerName(name)) {
            Log.e(TAG, "Invalid container name: " + name);
            return -1;
        }
        
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            File containerFile = new File(containerDir, name + BearModConstants.CONTAINER_EXTENSION);
            
            if (!containerFile.exists()) {
                Log.e(TAG, "Container does not exist: " + name);
                return -1;
            }
            
            return containerFile.length();
        } catch (Exception e) {
            Log.e(TAG, "Error getting container size", e);
            return -1;
        }
    }
    
    /**
     * Check if container exists
     * @param context Application context
     * @param name Container name
     * @return true if container exists, false otherwise
     */
    public static boolean containerExists(Context context, String name) {
        if (!BearModUtils.isValidContainerName(name)) {
            Log.e(TAG, "Invalid container name: " + name);
            return false;
        }
        
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            File containerFile = new File(containerDir, name + BearModConstants.CONTAINER_EXTENSION);
            
            return containerFile.exists();
        } catch (Exception e) {
            Log.e(TAG, "Error checking container existence", e);
            return false;
        }
    }
    
    /**
     * Get container count
     * @param context Application context
     * @return Number of containers
     */
    public static int getContainerCount(Context context) {
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            if (!containerDir.exists()) {
                return 0;
            }
            
            File[] files = containerDir.listFiles((dir, name) -> name.endsWith(BearModConstants.CONTAINER_EXTENSION));
            return files != null ? files.length : 0;
        } catch (Exception e) {
            Log.e(TAG, "Error getting container count", e);
            return 0;
        }
    }
    
    /**
     * Get total container size
     * @param context Application context
     * @return Total size of all containers in bytes
     */
    public static long getTotalContainerSize(Context context) {
        try {
            File containerDir = new File(context.getFilesDir(), BearModConstants.CONTAINER_DIR);
            if (!containerDir.exists()) {
                return 0;
            }
            
            File[] files = containerDir.listFiles((dir, name) -> name.endsWith(BearModConstants.CONTAINER_EXTENSION));
            if (files == null) {
                return 0;
            }
            
            long totalSize = 0;
            for (File file : files) {
                totalSize += file.length();
            }
            
            return totalSize;
        } catch (Exception e) {
            Log.e(TAG, "Error getting total container size", e);
            return 0;
        }
    }
} 