package com.bearmod.core.utils;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Logger class for debug output
 */
public class Logger {
    private static final String DEFAULT_TAG = "BearMod";
    private static String tag = DEFAULT_TAG;
    private static boolean initialized = false;
    private static boolean fileLoggingEnabled = false;
    private static File logFile = null;
    private static PrintWriter logWriter = null;
    
    /**
     * Initialize the logger
     * 
     * @param context Application context
     */
    public static void initialize(Context context) {
        if (initialized) {
            return;
        }
        
        tag = DEFAULT_TAG;
        
        // Initialize file logging if possible
        try {
            File logDir = context.getExternalFilesDir("logs");
            if (logDir != null) {
                if (!logDir.exists()) {
                    logDir.mkdirs();
                }
                
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US);
                String timestamp = sdf.format(new Date());
                
                logFile = new File(logDir, "bearmod_" + timestamp + ".log");
                logWriter = new PrintWriter(new FileOutputStream(logFile, true));
                
                fileLoggingEnabled = true;
                
                log(Log.INFO, "Logger initialized with file logging: " + logFile.getAbsolutePath());
            }
        } catch (IOException e) {
            Log.e(tag, "Failed to initialize file logging", e);
            fileLoggingEnabled = false;
        }
        
        initialized = true;
    }
    
    /**
     * Set the tag for log messages
     * 
     * @param newTag New tag
     */
    public static void setTag(String newTag) {
        tag = newTag;
    }
    
    /**
     * Log a debug message
     * 
     * @param message Message to log
     */
    public static void d(String message) {
        log(Log.DEBUG, message);
    }
    
    /**
     * Log an info message
     * 
     * @param message Message to log
     */
    public static void i(String message) {
        log(Log.INFO, message);
    }
    
    /**
     * Log a warning message
     * 
     * @param message Message to log
     */
    public static void w(String message) {
        log(Log.WARN, message);
    }
    
    /**
     * Log an error message
     * 
     * @param message Message to log
     */
    public static void e(String message) {
        log(Log.ERROR, message);
    }
    
    /**
     * Log an error message with an exception
     * 
     * @param message Message to log
     * @param throwable Exception to log
     */
    public static void e(String message, Throwable throwable) {
        Log.e(tag, message, throwable);
        
        if (fileLoggingEnabled && logWriter != null) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
            String timestamp = sdf.format(new Date());
            
            logWriter.println(timestamp + " E/" + tag + ": " + message);
            throwable.printStackTrace(logWriter);
            logWriter.flush();
        }
    }
    
    /**
     * Log a message with a specific level
     * 
     * @param level Log level
     * @param message Message to log
     */
    private static void log(int level, String message) {
        switch (level) {
            case Log.DEBUG:
                Log.d(tag, message);
                break;
            case Log.INFO:
                Log.i(tag, message);
                break;
            case Log.WARN:
                Log.w(tag, message);
                break;
            case Log.ERROR:
                Log.e(tag, message);
                break;
        }
        
        if (fileLoggingEnabled && logWriter != null) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
            String timestamp = sdf.format(new Date());
            
            String levelChar;
            switch (level) {
                case Log.DEBUG:
                    levelChar = "D";
                    break;
                case Log.INFO:
                    levelChar = "I";
                    break;
                case Log.WARN:
                    levelChar = "W";
                    break;
                case Log.ERROR:
                    levelChar = "E";
                    break;
                default:
                    levelChar = "?";
                    break;
            }
            
            logWriter.println(timestamp + " " + levelChar + "/" + tag + ": " + message);
            logWriter.flush();
        }
    }
    
    /**
     * Close the logger
     */
    public static void close() {
        if (fileLoggingEnabled && logWriter != null) {
            logWriter.close();
            logWriter = null;
        }
    }
}
