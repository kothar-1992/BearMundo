package com.bearmod.security.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.bearmod.security.BearModAuthenticator;
import com.bearmod.security.BearModContainerManager;
import com.bearmod.security.KeyAuthIntegrator;
import com.bearmod.security.SecurityPatches;

public class SecurityService extends Service {
    private static final String TAG = "SecurityService";
    private static final String CHANNEL_ID = "BearModSecurityChannel";
    private static final int NOTIFICATION_ID = 1;

    private BearModAuthenticator authenticator;
    private KeyAuthIntegrator keyAuth;
    private BearModContainerManager containerManager;
    private SecurityPatches securityPatches;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "SecurityService created");

        // Initialize security components
        authenticator = BearModAuthenticator.getInstance(this);
        keyAuth = KeyAuthIntegrator.getInstance(this);
        containerManager = BearModContainerManager.getInstance(this);
        securityPatches = SecurityPatches.getInstance(this);

        // Create notification channel for Android O and above
        createNotificationChannel();

        // Start as foreground service
        startForeground(NOTIFICATION_ID, createNotification());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "SecurityService started");

        // Initialize container manager
        containerManager.initialize();

        // Start security monitoring
        securityPatches.startMonitoring();

        // Return sticky to ensure service restarts if killed
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "SecurityService destroyed");

        // Stop security monitoring
        securityPatches.stopMonitoring();

        // Clean up container manager
        containerManager.cleanup();

        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "BearMod Security Service",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Security monitoring service");
            channel.setShowBadge(false);

            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private Notification createNotification() {
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("BearMod Security")
            .setContentText("Security monitoring active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true);

        return builder.build();
    }
} 