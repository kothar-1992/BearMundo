package com.bearmod.core.utils;

import android.content.Context;
import android.util.Log;

import com.bearmod.core.constants.BearModConstants;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Logging utility for BearMod library
 */
public final class BearModLogger {
    private static final String TAG = "BearModLogger";
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
    
    private static File logFile;
    private static FileOutputStream logStream;
    private static final AtomicInteger logCount = new AtomicInteger(0);
    private static boolean isInitialized = false;
    
    private BearModLogger() {
        // Prevent instantiation
    }
    
    /**
     * Initialize logger
     * @param context Application context
     * @return true if successful, false otherwise
     */
    public static synchronized boolean initialize(Context context) {
        if (isInitialized) {
            return true;
        }
        
        try {
            // Create log directory
            File logDir = new File(context.getFilesDir(), BearModConstants.LOG_DIR);
            if (!BearModUtils.createDirectory(logDir)) {
                Log.e(TAG, "Failed to create log directory");
                return false;
            }
            
            // Create log file
            logFile = new File(logDir, BearModConstants.LOG_FILE);
            logStream = new FileOutputStream(logFile, true);
            
            // Write header
            String header = String.format("=== BearMod Log Started at %s ===\n",
                DATE_FORMAT.format(new Date()));
            logStream.write(header.getBytes());
            
            isInitialized = true;
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to initialize logger", e);
            return false;
        }
    }
    
    /**
     * Cleanup logger
     */
    public static synchronized void cleanup() {
        if (!isInitialized) {
            return;
        }
        
        try {
            if (logStream != null) {
                String footer = String.format("=== BearMod Log Ended at %s ===\n",
                    DATE_FORMAT.format(new Date()));
                logStream.write(footer.getBytes());
                logStream.close();
            }
        } catch (IOException e) {
            Log.e(TAG, "Error during logger cleanup", e);
        } finally {
            logStream = null;
            logFile = null;
            isInitialized = false;
        }
    }
    
    /**
     * Log debug message
     * @param tag Log tag
     * @param message Log message
     */
    public static void d(String tag, String message) {
        Log.d(tag, message);
        writeLog("DEBUG", tag, message);
    }
    
    /**
     * Log info message
     * @param tag Log tag
     * @param message Log message
     */
    public static void i(String tag, String message) {
        Log.i(tag, message);
        writeLog("INFO", tag, message);
    }
    
    /**
     * Log warning message
     * @param tag Log tag
     * @param message Log message
     */
    public static void w(String tag, String message) {
        Log.w(tag, message);
        writeLog("WARN", tag, message);
    }
    
    /**
     * Log error message
     * @param tag Log tag
     * @param message Log message
     */
    public static void e(String tag, String message) {
        Log.e(tag, message);
        writeLog("ERROR", tag, message);
    }
    
    /**
     * Log error message with exception
     * @param tag Log tag
     * @param message Log message
     * @param throwable Exception
     */
    public static void e(String tag, String message, Throwable throwable) {
        Log.e(tag, message, throwable);
        writeLog("ERROR", tag, message + "\n" + Log.getStackTraceString(throwable));
    }
    
    /**
     * Write log to file
     * @param level Log level
     * @param tag Log tag
     * @param message Log message
     */
    private static synchronized void writeLog(String level, String tag, String message) {
        if (!isInitialized || logStream == null) {
            return;
        }
        
        try {
            // Check log file size
            if (logFile.length() >= BearModConstants.MAX_LOG_SIZE) {
                rotateLogFile();
            }
            
            // Format log entry
            String entry = String.format("%s [%s] %s - %s\n",
                DATE_FORMAT.format(new Date()),
                level,
                tag,
                message);
            
            // Write to file
            logStream.write(entry.getBytes());
            logStream.flush();
            
            // Increment log count
            logCount.incrementAndGet();
        } catch (IOException e) {
            Log.e(TAG, "Error writing to log file", e);
        }
    }
    
    /**
     * Rotate log file
     */
    private static void rotateLogFile() {
        try {
            // Close current log stream
            if (logStream != null) {
                logStream.close();
            }
            
            // Rename current log file
            File logDir = logFile.getParentFile();
            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
            File oldLogFile = new File(logDir, String.format("bearmod_%s.log", timestamp));
            logFile.renameTo(oldLogFile);
            
            // Create new log file
            logFile = new File(logDir, BearModConstants.LOG_FILE);
            logStream = new FileOutputStream(logFile, true);
            
            // Write header
            String header = String.format("=== BearMod Log Started at %s ===\n",
                DATE_FORMAT.format(new Date()));
            logStream.write(header.getBytes());
            
            // Delete old log files if exceeding max count
            File[] logFiles = logDir.listFiles((dir, name) -> name.startsWith("bearmod_") && name.endsWith(".log"));
            if (logFiles != null && logFiles.length > BearModConstants.MAX_LOG_FILES) {
                // Sort by last modified time
                java.util.Arrays.sort(logFiles, (f1, f2) -> Long.compare(f2.lastModified(), f1.lastModified()));
                
                // Delete oldest files
                for (int i = BearModConstants.MAX_LOG_FILES; i < logFiles.length; i++) {
                    logFiles[i].delete();
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error rotating log file", e);
        }
    }
    
    /**
     * Get log count
     * @return Number of log entries
     */
    public static int getLogCount() {
        return logCount.get();
    }
    
    /**
     * Reset log count
     */
    public static void resetLogCount() {
        logCount.set(0);
    }
} 