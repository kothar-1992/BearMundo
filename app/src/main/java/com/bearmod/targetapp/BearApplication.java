package com.bearmod.targetapp;

import android.app.Application;
import android.util.Log;

import com.bearmod.NativeUtils;

import timber.log.Timber;

/**
 * Custom Application class for initialization
 */
public class BearApplication extends Application {
    private static final String TAG = "BearApplication";

    @Override
    public void onCreate() {
        super.onCreate();
        
        // Initialize Timber for better logging
        if (BuildConfig.DEBUG) {
            Timber.plant(new Timber.DebugTree());
        } else {
            // Custom release tree that logs to Crashlytics or other services
            Timber.plant(new ReleaseTree());
        }
        
        Timber.i("Application initialized");
        
        // Initialize native code
        boolean initialized = NativeUtils.initialize(this);
        Timber.i("Native code initialization: %s", initialized ? "success" : "failed");
    }

    @Override
    public void onTerminate() {
        // Clean up native resources
        NativeUtils.cleanup();
        Timber.i("Application terminated, native resources cleaned up");
        
        super.onTerminate();
    }
    
    /**
     * Custom Timber tree for release builds
     */
    private static class ReleaseTree extends Timber.Tree {
        @Override
        protected void log(int priority, String tag, String message, Throwable t) {
            if (priority < Log.INFO) {
                return; // Only log INFO and above in release builds
            }
            
            // Log to Android's log system
            Log.println(priority, tag, message);
            
            // Here you could also log to a crash reporting service like Firebase Crashlytics
            // For example:
            // if (priority >= Log.ERROR) {
            //     Crashlytics.log(priority, tag, message);
            //     if (t != null) {
            //         Crashlytics.logException(t);
            //     }
            // }
        }
    }
}
