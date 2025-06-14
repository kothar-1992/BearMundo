package com.bearmod.core.constants;

/**
 * Constants used throughout the BearMod library
 */
public final class BearModConstants {
    private BearModConstants() {
        // Prevent instantiation
    }
    
    // Library version
    public static final String LIBRARY_VERSION = "1.0.0";
    public static final int LIBRARY_VERSION_CODE = 1;
    
    // Package names
    public static final String PACKAGE_NAME = "com.bearmod";
    public static final String NATIVE_LIB_NAME = "bearmod";
    
    // File paths
    public static final String CONTAINER_DIR = "containers";
    public static final String LOG_DIR = "logs";
    public static final String CACHE_DIR = "cache";
    public static final String CONFIG_DIR = "config";
    
    // File names
    public static final String CONFIG_FILE = "bearmod_config.json";
    public static final String LOG_FILE = "bearmod.log";
    public static final String CACHE_FILE = "bearmod_cache.dat";
    
    // Security constants
    public static final int MAX_LOGIN_ATTEMPTS = 3;
    public static final long LOGIN_TIMEOUT_MS = 300000; // 5 minutes
    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int MAX_PASSWORD_LENGTH = 64;
    
    // Container constants
    public static final int MAX_CONTAINERS = 10;
    public static final long MAX_CONTAINER_SIZE = 1024 * 1024 * 1024; // 1GB
    public static final String CONTAINER_EXTENSION = ".bear";
    
    // Feature flags
    public static final boolean ENABLE_SSL_BYPASS = true;
    public static final boolean ENABLE_ROOT_BYPASS = true;
    public static final boolean ENABLE_DEBUG_BYPASS = true;
    public static final boolean ENABLE_EMULATOR_BYPASS = true;
    public static final boolean ENABLE_SIGNATURE_BYPASS = true;
    public static final boolean ENABLE_FRIDA_DETECTION = true;
    public static final boolean ENABLE_MEMORY_PROTECTION = true;
    public static final boolean ENABLE_REAL_TIME_ANALYSIS = true;
    public static final boolean ENABLE_SECURITY_MONITORING = true;
    public static final boolean ENABLE_CUSTOM_HOOKS = true;
    
    // Timeouts
    public static final long DEFAULT_TIMEOUT_MS = 30000; // 30 seconds
    public static final long CONNECTION_TIMEOUT_MS = 10000; // 10 seconds
    public static final long READ_TIMEOUT_MS = 30000; // 30 seconds
    public static final long WRITE_TIMEOUT_MS = 30000; // 30 seconds
    
    // Cache settings
    public static final long CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours
    public static final int MAX_CACHE_SIZE = 100 * 1024 * 1024; // 100MB
    
    // Logging
    public static final int MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
    public static final int MAX_LOG_FILES = 5;
    public static final String LOG_PATTERN = "%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n";
    
    // Error messages
    public static final String ERROR_INITIALIZATION = "Failed to initialize BearMod library";
    public static final String ERROR_CLEANUP = "Failed to cleanup BearMod library";
    public static final String ERROR_CONTAINER_CREATION = "Failed to create container";
    public static final String ERROR_CONTAINER_ACCESS = "Failed to access container";
    public static final String ERROR_AUTHENTICATION = "Authentication failed";
    public static final String ERROR_SECURITY = "Security check failed";
    public static final String ERROR_FEATURE = "Feature not available";
    public static final String ERROR_CONFIGURATION = "Invalid configuration";
    
    // Success messages
    public static final String SUCCESS_INITIALIZATION = "BearMod library initialized successfully";
    public static final String SUCCESS_CLEANUP = "BearMod library cleaned up successfully";
    public static final String SUCCESS_CONTAINER_CREATION = "Container created successfully";
    public static final String SUCCESS_CONTAINER_ACCESS = "Container accessed successfully";
    public static final String SUCCESS_AUTHENTICATION = "Authentication successful";
    public static final String SUCCESS_SECURITY = "Security check passed";
    public static final String SUCCESS_FEATURE = "Feature enabled successfully";
    public static final String SUCCESS_CONFIGURATION = "Configuration applied successfully";
} 