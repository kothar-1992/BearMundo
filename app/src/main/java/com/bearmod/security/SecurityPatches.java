package com.bearmod.security;

import android.content.Context;
import android.os.Process;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SecurityPatches {
    private static final String TAG = "SecurityPatches";
    private static SecurityPatches instance;
    private final Context context;
    private final ScheduledExecutorService monitorExecutor;
    private final Set<String> suspiciousThreads;
    private final Set<String> suspiciousProcesses;
    private boolean isMonitoring;
    private long lastMemoryCheck;
    private static final long MEMORY_CHECK_INTERVAL = 5000; // 5 seconds
    private static final long MEMORY_THRESHOLD = 100 * 1024 * 1024; // 100MB

    private SecurityPatches(Context context) {
        this.context = context.getApplicationContext();
        this.monitorExecutor = Executors.newSingleThreadScheduledExecutor();
        this.suspiciousThreads = new HashSet<>();
        this.suspiciousProcesses = new HashSet<>();
        this.isMonitoring = false;
        this.lastMemoryCheck = 0;
    }

    public static synchronized SecurityPatches getInstance(Context context) {
        if (instance == null) {
            instance = new SecurityPatches(context);
        }
        return instance;
    }

    public void startMonitoring() {
        if (isMonitoring) {
            return;
        }

        isMonitoring = true;
        monitorExecutor.scheduleAtFixedRate(this::checkForHooks, 0, 1, TimeUnit.SECONDS);
        monitorExecutor.scheduleAtFixedRate(this::checkMemoryUsage, 0, 5, TimeUnit.SECONDS);
        monitorExecutor.scheduleAtFixedRate(this::checkSuspiciousProcesses, 0, 2, TimeUnit.SECONDS);
        Log.d(TAG, "Security monitoring started");
    }

    public void stopMonitoring() {
        if (!isMonitoring) {
            return;
        }

        isMonitoring = false;
        monitorExecutor.shutdown();
        try {
            if (!monitorExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                monitorExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            monitorExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        Log.d(TAG, "Security monitoring stopped");
    }

    private void checkForHooks() {
        if (!isMonitoring) return;

        // Check for Frida
        if (isFridaDetected()) {
            Log.e(TAG, "Frida detected!");
            handleSecurityViolation("Frida hook detected");
        }

        // Check for Xposed
        if (isXposedDetected()) {
            Log.e(TAG, "Xposed detected!");
            handleSecurityViolation("Xposed framework detected");
        }

        // Check for suspicious threads
        checkSuspiciousThreads();
    }

    private boolean isFridaDetected() {
        // Check for Frida server
        String[] fridaPaths = {
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/sdcard/frida-server",
            "/sdcard/re.frida.server"
        };

        for (String path : fridaPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        // Check for Frida libraries
        try {
            Process process = Runtime.getRuntime().exec("ps -A");
            BufferedReader reader = new BufferedReader(new FileReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || line.contains("gum-js-loop")) {
                    return true;
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking for Frida", e);
        }

        return false;
    }

    private boolean isXposedDetected() {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (ClassNotFoundException e) {
            // Xposed not found
        }

        // Check for Xposed modules
        String[] xposedPaths = {
            "/data/app/de.robv.android.xposed.installer-1",
            "/data/app/de.robv.android.xposed.installer-2",
            "/data/data/de.robv.android.xposed.installer"
        };

        for (String path : xposedPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        return false;
    }

    private void checkSuspiciousThreads() {
        if (!isMonitoring) return;

        ThreadGroup rootGroup = Thread.currentThread().getThreadGroup();
        while (rootGroup.getParent() != null) {
            rootGroup = rootGroup.getParent();
        }

        Thread[] threads = new Thread[rootGroup.activeCount()];
        rootGroup.enumerate(threads);

        for (Thread thread : threads) {
            if (thread != null) {
                String threadName = thread.getName().toLowerCase();
                if (isSuspiciousThreadName(threadName)) {
                    suspiciousThreads.add(threadName);
                    Log.w(TAG, "Suspicious thread detected: " + threadName);
                }
            }
        }
    }

    private boolean isSuspiciousThreadName(String threadName) {
        String[] suspiciousPatterns = {
            "frida",
            "xposed",
            "substrate",
            "magisk",
            "supersu",
            "rootcloak",
            "hide",
            "inject",
            "hook",
            "debug"
        };

        return Arrays.stream(suspiciousPatterns)
            .anyMatch(pattern -> threadName.contains(pattern));
    }

    private void checkMemoryUsage() {
        if (!isMonitoring) return;

        long currentTime = System.currentTimeMillis();
        if (currentTime - lastMemoryCheck < MEMORY_CHECK_INTERVAL) {
            return;
        }

        lastMemoryCheck = currentTime;
        Runtime runtime = Runtime.getRuntime();
        long usedMemory = runtime.totalMemory() - runtime.freeMemory();

        if (usedMemory > MEMORY_THRESHOLD) {
            Log.w(TAG, "High memory usage detected: " + (usedMemory / 1024 / 1024) + "MB");
            // Trigger memory cleanup
            System.gc();
        }
    }

    private void checkSuspiciousProcesses() {
        if (!isMonitoring) return;

        try {
            Process process = Runtime.getRuntime().exec("ps -A");
            BufferedReader reader = new BufferedReader(new FileReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (isSuspiciousProcess(line)) {
                    String processName = extractProcessName(line);
                    if (processName != null) {
                        suspiciousProcesses.add(processName);
                        Log.w(TAG, "Suspicious process detected: " + processName);
                    }
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error checking suspicious processes", e);
        }
    }

    private boolean isSuspiciousProcess(String processLine) {
        String[] suspiciousPatterns = {
            "frida",
            "xposed",
            "magisk",
            "supersu",
            "rootcloak",
            "hide",
            "inject",
            "hook",
            "debug"
        };

        return Arrays.stream(suspiciousPatterns)
            .anyMatch(pattern -> processLine.toLowerCase().contains(pattern));
    }

    private String extractProcessName(String processLine) {
        String[] parts = processLine.trim().split("\\s+");
        if (parts.length > 8) {
            return parts[8];
        }
        return null;
    }

    private void handleSecurityViolation(String reason) {
        Log.e(TAG, "Security violation: " + reason);
        // Notify native layer
        nativeHandleSecurityViolation(reason);
        // Stop monitoring
        stopMonitoring();
        // Exit process
        Process.killProcess(Process.myPid());
    }

    private native void nativeHandleSecurityViolation(String reason);

    public Set<String> getSuspiciousThreads() {
        return new HashSet<>(suspiciousThreads);
    }

    public Set<String> getSuspiciousProcesses() {
        return new HashSet<>(suspiciousProcesses);
    }

    public boolean isMonitoring() {
        return isMonitoring;
    }
} 