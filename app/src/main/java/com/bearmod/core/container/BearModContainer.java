package com.bearmod.core.container;

import android.util.Log;

import com.bearmod.core.auth.HostContext;
import com.bearmod.core.hooks.IsolatedHookManager;
import com.bearmod.core.security.IsolatedSecurityAnalyzer;
import com.bearmod.core.data.IsolatedDataStore;
import com.bearmod.core.events.IsolatedEventBus;
import com.bearmod.core.plugins.BearModPluginManager;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Isolated container for BearMod functionality
 * Provides complete isolation between different host applications
 */
public class BearModContainer {
    
    private static final String TAG = "BearModContainer";
    
    private final String id;
    private final HostContext hostContext;
    private final ContainerConfig config;
    private final AtomicBoolean initialized;
    private final AtomicBoolean destroyed;
    
    // Isolated components
    private IsolatedHookManager hookManager;
    private IsolatedSecurityAnalyzer securityAnalyzer;
    private IsolatedDataStore dataStore;
    private IsolatedEventBus eventBus;
    private BearModPluginManager pluginManager;
    
    // Container state
    private final Map<String, Object> containerState;
    private final long createdAt;
    private long lastAccessTime;
    
    public BearModContainer(String id, HostContext hostContext, ContainerConfig config) {
        this.id = id;
        this.hostContext = hostContext;
        this.config = config;
        this.initialized = new AtomicBoolean(false);
        this.destroyed = new AtomicBoolean(false);
        this.containerState = new ConcurrentHashMap<>();
        this.createdAt = System.currentTimeMillis();
        this.lastAccessTime = createdAt;
        
        Log.i(TAG, "Created container: " + id + " for host: " + hostContext.getHostId());
    }
    
    /**
     * Initialize container and all isolated components
     */
    public InitializationResult initialize() {
        if (initialized.get()) {
            return InitializationResult.success(this);
        }
        
        if (destroyed.get()) {
            return InitializationResult.failure("Container has been destroyed");
        }
        
        try {
            Log.i(TAG, "Initializing container: " + id);
            
            // Initialize isolated components based on configuration
            initializeHookManager();
            initializeSecurityAnalyzer();
            initializeDataStore();
            initializeEventBus();
            initializePluginManager();
            
            // Set up inter-component communication
            setupComponentCommunication();
            
            // Apply security policies
            applySecurityPolicies();
            
            initialized.set(true);
            updateLastAccessTime();
            
            Log.i(TAG, "Container initialized successfully: " + id);
            return InitializationResult.success(this);
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize container: " + id, e);
            cleanup(); // Cleanup partial initialization
            return InitializationResult.failure("Container initialization failed", e);
        }
    }
    
    /**
     * Get isolated hook manager for this container
     */
    public IsolatedHookManager getHookManager() {
        ensureInitialized();
        updateLastAccessTime();
        return hookManager;
    }
    
    /**
     * Get isolated security analyzer for this container
     */
    public IsolatedSecurityAnalyzer getSecurityAnalyzer() {
        ensureInitialized();
        updateLastAccessTime();
        return securityAnalyzer;
    }
    
    /**
     * Get isolated data store for this container
     */
    public IsolatedDataStore getDataStore() {
        ensureInitialized();
        updateLastAccessTime();
        return dataStore;
    }
    
    /**
     * Get isolated event bus for this container
     */
    public IsolatedEventBus getEventBus() {
        ensureInitialized();
        updateLastAccessTime();
        return eventBus;
    }
    
    /**
     * Get plugin manager for this container
     */
    public BearModPluginManager getPluginManager() {
        ensureInitialized();
        updateLastAccessTime();
        return pluginManager;
    }
    
    /**
     * Set container state value
     */
    public void setState(String key, Object value) {
        ensureInitialized();
        containerState.put(key, value);
        updateLastAccessTime();
    }
    
    /**
     * Get container state value
     */
    @SuppressWarnings("unchecked")
    public <T> T getState(String key, Class<T> type) {
        ensureInitialized();
        updateLastAccessTime();
        Object value = containerState.get(key);
        return type.isInstance(value) ? (T) value : null;
    }
    
    /**
     * Check if container is initialized
     */
    public boolean isInitialized() {
        return initialized.get() && !destroyed.get();
    }
    
    /**
     * Check if container is destroyed
     */
    public boolean isDestroyed() {
        return destroyed.get();
    }
    
    /**
     * Get container information
     */
    public ContainerInfo getInfo() {
        return new ContainerInfo(
            id,
            hostContext,
            config,
            isInitialized(),
            isDestroyed(),
            createdAt,
            lastAccessTime,
            containerState.size()
        );
    }
    
    /**
     * Cleanup container and all resources
     */
    public void cleanup() {
        if (destroyed.getAndSet(true)) {
            return; // Already destroyed
        }
        
        Log.i(TAG, "Cleaning up container: " + id);
        
        try {
            // Cleanup components in reverse order
            if (pluginManager != null) {
                pluginManager.cleanup();
            }
            
            if (eventBus != null) {
                eventBus.cleanup();
            }
            
            if (dataStore != null) {
                dataStore.cleanup();
            }
            
            if (securityAnalyzer != null) {
                securityAnalyzer.cleanup();
            }
            
            if (hookManager != null) {
                hookManager.cleanup();
            }
            
            // Clear container state
            containerState.clear();
            
            Log.i(TAG, "Container cleaned up: " + id);
            
        } catch (Exception e) {
            Log.e(TAG, "Error during container cleanup: " + id, e);
        }
    }
    
    // Getters
    public String getId() { return id; }
    public HostContext getHostContext() { return hostContext; }
    public ContainerConfig getConfig() { return config; }
    public long getCreatedAt() { return createdAt; }
    public long getLastAccessTime() { return lastAccessTime; }
    
    /**
     * Initialize hook manager with isolation
     */
    private void initializeHookManager() {
        hookManager = new IsolatedHookManager(this);
        hookManager.initialize();
        Log.d(TAG, "Hook manager initialized for container: " + id);
    }
    
    /**
     * Initialize security analyzer with isolation
     */
    private void initializeSecurityAnalyzer() {
        securityAnalyzer = new IsolatedSecurityAnalyzer(this);
        securityAnalyzer.initialize();
        Log.d(TAG, "Security analyzer initialized for container: " + id);
    }
    
    /**
     * Initialize data store with isolation
     */
    private void initializeDataStore() {
        dataStore = new IsolatedDataStore(this);
        dataStore.initialize();
        Log.d(TAG, "Data store initialized for container: " + id);
    }
    
    /**
     * Initialize event bus with isolation
     */
    private void initializeEventBus() {
        eventBus = new IsolatedEventBus(this);
        eventBus.initialize();
        Log.d(TAG, "Event bus initialized for container: " + id);
    }
    
    /**
     * Initialize plugin manager
     */
    private void initializePluginManager() {
        pluginManager = new BearModPluginManager(this);
        pluginManager.initialize();
        Log.d(TAG, "Plugin manager initialized for container: " + id);
    }
    
    /**
     * Setup communication between components
     */
    private void setupComponentCommunication() {
        // Connect hook manager to event bus
        hookManager.setEventBus(eventBus);
        
        // Connect security analyzer to event bus
        securityAnalyzer.setEventBus(eventBus);
        
        // Connect data store to event bus
        dataStore.setEventBus(eventBus);
        
        Log.d(TAG, "Component communication setup for container: " + id);
    }
    
    /**
     * Apply security policies to container
     */
    private void applySecurityPolicies() {
        SecurityPolicy policy = config.getSecurityPolicy();
        if (policy != null) {
            // Apply hook restrictions
            hookManager.applySecurityPolicy(policy);
            
            // Apply security analyzer policies
            securityAnalyzer.applySecurityPolicy(policy);
            
            // Apply data store policies
            dataStore.applySecurityPolicy(policy);
            
            Log.d(TAG, "Security policies applied for container: " + id);
        }
    }
    
    /**
     * Ensure container is initialized before use
     */
    private void ensureInitialized() {
        if (!initialized.get()) {
            throw new IllegalStateException("Container not initialized: " + id);
        }
        
        if (destroyed.get()) {
            throw new IllegalStateException("Container has been destroyed: " + id);
        }
    }
    
    /**
     * Update last access time
     */
    private void updateLastAccessTime() {
        lastAccessTime = System.currentTimeMillis();
    }
}

/**
 * Container information class
 */
class ContainerInfo {
    private final String id;
    private final HostContext hostContext;
    private final ContainerConfig config;
    private final boolean initialized;
    private final boolean destroyed;
    private final long createdAt;
    private final long lastAccessTime;
    private final int stateSize;
    
    public ContainerInfo(String id, HostContext hostContext, ContainerConfig config,
                        boolean initialized, boolean destroyed, long createdAt,
                        long lastAccessTime, int stateSize) {
        this.id = id;
        this.hostContext = hostContext;
        this.config = config;
        this.initialized = initialized;
        this.destroyed = destroyed;
        this.createdAt = createdAt;
        this.lastAccessTime = lastAccessTime;
        this.stateSize = stateSize;
    }
    
    // Getters
    public String getId() { return id; }
    public HostContext getHostContext() { return hostContext; }
    public ContainerConfig getConfig() { return config; }
    public boolean isInitialized() { return initialized; }
    public boolean isDestroyed() { return destroyed; }
    public long getCreatedAt() { return createdAt; }
    public long getLastAccessTime() { return lastAccessTime; }
    public int getStateSize() { return stateSize; }
    
    public long getAge() {
        return System.currentTimeMillis() - createdAt;
    }
    
    public long getIdleTime() {
        return System.currentTimeMillis() - lastAccessTime;
    }
    
    @Override
    public String toString() {
        return String.format("ContainerInfo{id='%s', host='%s', initialized=%s, destroyed=%s, age=%dms, idle=%dms}",
                           id, hostContext.getHostId(), initialized, destroyed, getAge(), getIdleTime());
    }
}
