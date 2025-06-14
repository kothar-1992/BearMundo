package com.bearmod.core.container;

import android.util.Log;

import com.bearmod.core.auth.HostContext;
import com.bearmod.core.config.BearModConfiguration;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.Map;
import java.util.UUID;

/**
 * Container manager for multi-tenant BearMod AAR support
 * Provides isolated execution environments for different host applications
 */
public class BearModContainerManager {
    
    private static final String TAG = "BearModContainerManager";
    private static BearModContainerManager instance;
    
    private final Map<String, BearModContainer> containers;
    private final Map<String, String> hostToContainerMapping;
    private final ReentrantReadWriteLock containerLock;
    
    private BearModContainerManager() {
        this.containers = new ConcurrentHashMap<>();
        this.hostToContainerMapping = new ConcurrentHashMap<>();
        this.containerLock = new ReentrantReadWriteLock();
    }
    
    public static synchronized BearModContainerManager getInstance() {
        if (instance == null) {
            instance = new BearModContainerManager();
        }
        return instance;
    }
    
    /**
     * Create a new isolated container for a host application
     */
    public BearModContainer createContainer(HostContext hostContext, ContainerConfig config) {
        containerLock.writeLock().lock();
        try {
            // Check if container already exists for this host
            String existingContainerId = hostToContainerMapping.get(hostContext.getHostId());
            if (existingContainerId != null) {
                BearModContainer existingContainer = containers.get(existingContainerId);
                if (existingContainer != null && !existingContainer.isDestroyed()) {
                    Log.i(TAG, "Returning existing container for host: " + hostContext.getHostId());
                    return existingContainer;
                }
            }
            
            // Generate unique container ID
            String containerId = generateContainerId(hostContext);
            
            // Create new container
            BearModContainer container = new BearModContainer(
                containerId,
                hostContext,
                config
            );
            
            // Initialize container
            InitializationResult initResult = container.initialize();
            if (!initResult.isSuccess()) {
                Log.e(TAG, "Failed to initialize container: " + initResult.getErrorMessage());
                throw new RuntimeException("Container initialization failed: " + initResult.getErrorMessage());
            }
            
            // Store container
            containers.put(containerId, container);
            hostToContainerMapping.put(hostContext.getHostId(), containerId);
            
            Log.i(TAG, "Created new container: " + containerId + " for host: " + hostContext.getHostId());
            return container;
            
        } finally {
            containerLock.writeLock().unlock();
        }
    }
    
    /**
     * Get container by ID
     */
    public BearModContainer getContainer(String containerId) {
        containerLock.readLock().lock();
        try {
            return containers.get(containerId);
        } finally {
            containerLock.readLock().unlock();
        }
    }
    
    /**
     * Get container by host ID
     */
    public BearModContainer getContainerByHost(String hostId) {
        containerLock.readLock().lock();
        try {
            String containerId = hostToContainerMapping.get(hostId);
            return containerId != null ? containers.get(containerId) : null;
        } finally {
            containerLock.readLock().unlock();
        }
    }
    
    /**
     * Destroy container and cleanup resources
     */
    public void destroyContainer(String containerId) {
        containerLock.writeLock().lock();
        try {
            BearModContainer container = containers.get(containerId);
            if (container != null) {
                container.cleanup();
                containers.remove(containerId);
                hostToContainerMapping.remove(container.getHostContext().getHostId());
                Log.i(TAG, "Destroyed container: " + containerId);
            }
        } finally {
            containerLock.writeLock().unlock();
        }
    }
    
    /**
     * Generate unique container ID
     */
    private String generateContainerId(HostContext hostContext) {
        return UUID.randomUUID().toString();
    }
    
    /**
     * Get all active containers
     */
    public Map<String, BearModContainer> getActiveContainers() {
        containerLock.readLock().lock();
        try {
            return new ConcurrentHashMap<>(containers);
        } finally {
            containerLock.readLock().unlock();
        }
    }
    
    /**
     * Cleanup all containers
     */
    public void cleanupAll() {
        containerLock.writeLock().lock();
        try {
            for (BearModContainer container : containers.values()) {
                container.cleanup();
            }
            containers.clear();
            hostToContainerMapping.clear();
            Log.i(TAG, "Cleaned up all containers");
        } finally {
            containerLock.writeLock().unlock();
        }
    }
}

/**
 * Container configuration
 */
class ContainerConfig {
    private final IsolationLevel isolationLevel;
    private final SecurityPolicy securityPolicy;
    private final BearModConfiguration configuration;
    private final Map<String, Object> customProperties;
    
    private ContainerConfig(Builder builder) {
        this.isolationLevel = builder.isolationLevel;
        this.securityPolicy = builder.securityPolicy;
        this.configuration = builder.configuration;
        this.customProperties = builder.customProperties;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    // Getters
    public IsolationLevel getIsolationLevel() { return isolationLevel; }
    public SecurityPolicy getSecurityPolicy() { return securityPolicy; }
    public BearModConfiguration getConfiguration() { return configuration; }
    public Map<String, Object> getCustomProperties() { return customProperties; }
    
    public static class Builder {
        private IsolationLevel isolationLevel = IsolationLevel.MEDIUM;
        private SecurityPolicy securityPolicy;
        private BearModConfiguration configuration;
        private Map<String, Object> customProperties = new ConcurrentHashMap<>();
        
        public Builder setIsolationLevel(IsolationLevel isolationLevel) {
            this.isolationLevel = isolationLevel;
            return this;
        }
        
        public Builder setSecurityPolicy(SecurityPolicy securityPolicy) {
            this.securityPolicy = securityPolicy;
            return this;
        }
        
        public Builder setConfiguration(BearModConfiguration configuration) {
            this.configuration = configuration;
            return this;
        }
        
        public Builder setCustomProperty(String key, Object value) {
            this.customProperties.put(key, value);
            return this;
        }
        
        public ContainerConfig build() {
            return new ContainerConfig(this);
        }
    }
}

/**
 * Container isolation levels
 */
enum IsolationLevel {
    BASIC,      // Basic process isolation
    MEDIUM,     // Process + data isolation
    FULL        // Complete isolation with separate security contexts
}

/**
 * Container statistics
 */
class ContainerStatistics {
    private final int totalContainers;
    private final int activeContainers;
    private final int destroyedContainers;
    
    public ContainerStatistics(int totalContainers, int activeContainers, int destroyedContainers) {
        this.totalContainers = totalContainers;
        this.activeContainers = activeContainers;
        this.destroyedContainers = destroyedContainers;
    }
    
    // Getters
    public int getTotalContainers() { return totalContainers; }
    public int getActiveContainers() { return activeContainers; }
    public int getDestroyedContainers() { return destroyedContainers; }
    
    @Override
    public String toString() {
        return String.format("ContainerStatistics{total=%d, active=%d, destroyed=%d}", 
                           totalContainers, activeContainers, destroyedContainers);
    }
}

/**
 * Container initialization result
 */
class InitializationResult {
    private final boolean success;
    private final String errorMessage;
    private final Exception exception;
    private final BearModContainer container;
    
    private InitializationResult(boolean success, String errorMessage, 
                               Exception exception, BearModContainer container) {
        this.success = success;
        this.errorMessage = errorMessage;
        this.exception = exception;
        this.container = container;
    }
    
    public static InitializationResult success(BearModContainer container) {
        return new InitializationResult(true, null, null, container);
    }
    
    public static InitializationResult failure(String errorMessage) {
        return new InitializationResult(false, errorMessage, null, null);
    }
    
    public static InitializationResult failure(String errorMessage, Exception exception) {
        return new InitializationResult(false, errorMessage, exception, null);
    }
    
    // Getters
    public boolean isSuccess() { return success; }
    public String getErrorMessage() { return errorMessage; }
    public Exception getException() { return exception; }
    public BearModContainer getContainer() { return container; }
}
