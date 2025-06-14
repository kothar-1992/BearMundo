package com.bearmod.utils;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for file operations
 */
public class FileUtils {
    private static final String TAG = "FileUtils";

    /**
     * Read text from a file
     * 
     * @param file The file to read from
     * @return The content of the file as a string
     */
    public static String readFile(File file) {
        StringBuilder content = new StringBuilder();
        
        try (FileInputStream fis = new FileInputStream(file);
             InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
             BufferedReader reader = new BufferedReader(isr)) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (IOException e) {
            Log.e(TAG, "Error reading file: " + file.getAbsolutePath(), e);
        }
        
        return content.toString();
    }
    
    /**
     * Write text to a file
     * 
     * @param file The file to write to
     * @param content The content to write
     * @return true if successful, false otherwise
     */
    public static boolean writeFile(File file, String content) {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Error writing to file: " + file.getAbsolutePath(), e);
            return false;
        }
    }
    
    /**
     * Delete a file or directory
     * 
     * @param file The file or directory to delete
     * @return true if successful, false otherwise
     */
    public static boolean delete(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    delete(child);
                }
            }
        }
        return file.delete();
    }
    
    /**
     * Get the app's private files directory
     * 
     * @param context The application context
     * @return The app's private files directory
     */
    public static File getAppFilesDir(Context context) {
        return context.getFilesDir();
    }
    
    /**
     * Get the app's private cache directory
     * 
     * @param context The application context
     * @return The app's private cache directory
     */
    public static File getAppCacheDir(Context context) {
        return context.getCacheDir();
    }
}
