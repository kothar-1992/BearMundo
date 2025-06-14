package com.bearmod.security;

import android.content.Context;
import android.util.Log;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public class BearModContainerManager {
    private static final String TAG = "BearModContainerManager";
    private static BearModContainerManager instance;
    private final Context context;
    private final Map<String, BearModContainer> containers;
    private final AtomicBoolean isInitialized;

    private BearModContainerManager(Context context) {
        this.context = context.getApplicationContext();
        this.containers = new ConcurrentHashMap<>();
        this.isInitialized = new AtomicBoolean(false);
    }

    public static synchronized BearModContainerManager getInstance(Context context) {
        if (instance == null) {
            instance = new BearModContainerManager(context);
        }
        return instance;
    }

    public BearModContainer createContainer(String containerId) {
        if (!isInitialized.get()) {
            throw new IllegalStateException("ContainerManager not initialized");
        }

        if (containers.containsKey(containerId)) {
            Log.w(TAG, "Container already exists: " + containerId);
            return containers.get(containerId);
        }

        BearModContainer container = new BearModContainer(containerId, context);
        containers.put(containerId, container);
        Log.d(TAG, "Created new container: " + containerId);
        return container;
    }

    public BearModContainer getContainer(String containerId) {
        if (!isInitialized.get()) {
            throw new IllegalStateException("ContainerManager not initialized");
        }

        BearModContainer container = containers.get(containerId);
        if (container == null) {
            throw new IllegalArgumentException("Container not found: " + containerId);
        }
        return container;
    }

    public void removeContainer(String containerId) {
        if (!isInitialized.get()) {
            throw new IllegalStateException("ContainerManager not initialized");
        }

        BearModContainer container = containers.remove(containerId);
        if (container != null) {
            container.cleanup();
            Log.d(TAG, "Removed container: " + containerId);
        }
    }

    public void initialize() {
        if (isInitialized.compareAndSet(false, true)) {
            // Initialize native components
            System.loadLibrary("bearmundo-security");
            Log.d(TAG, "ContainerManager initialized");
        }
    }

    public void cleanup() {
        if (isInitialized.compareAndSet(true, false)) {
            // Clean up all containers
            for (Map.Entry<String, BearModContainer> entry : containers.entrySet()) {
                entry.getValue().cleanup();
            }
            containers.clear();
            Log.d(TAG, "ContainerManager cleaned up");
        }
    }

    public static class BearModContainer {
        private final String containerId;
        private final Context context;
        private final AtomicBoolean isActive;
        private final Map<String, Object> sharedData;

        private BearModContainer(String containerId, Context context) {
            this.containerId = containerId;
            this.context = context;
            this.isActive = new AtomicBoolean(true);
            this.sharedData = new ConcurrentHashMap<>();
        }

        public String getContainerId() {
            return containerId;
        }

        public boolean isActive() {
            return isActive.get();
        }

        public void setSharedData(String key, Object value) {
            if (!isActive.get()) {
                throw new IllegalStateException("Container is not active");
            }
            sharedData.put(key, value);
        }

        public Object getSharedData(String key) {
            if (!isActive.get()) {
                throw new IllegalStateException("Container is not active");
            }
            return sharedData.get(key);
        }

        public void cleanup() {
            if (isActive.compareAndSet(true, false)) {
                sharedData.clear();
                // Clean up native resources
                nativeCleanupContainer(containerId);
            }
        }

        private native void nativeCleanupContainer(String containerId);
    }
} 