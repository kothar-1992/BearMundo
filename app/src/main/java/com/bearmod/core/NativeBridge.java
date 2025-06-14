package com.bearmod.core;

/**
 * Bridge class for native methods
 * 
 * This class provides a Java interface to the native C++ code
 */
public class NativeBridge {
    // Load the native library
    static {
        System.loadLibrary("bearmod");
    }
    
    /**
     * Initialize the native library
     * 
     * @return true if initialization was successful, false otherwise
     */
    public static native boolean initialize();
    
    /**
     * Hook a function by name
     * 
     * @param libraryName Name of the library containing the function
     * @param functionName Name of the function to hook
     * @param hookType Type of hook to apply
     * @return true if hooking was successful, false otherwise
     */
    public static native boolean hookFunction(String libraryName, String functionName, int hookType);
    
    /**
     * Read memory from a specific address
     * 
     * @param address Address to read from
     * @param buffer Buffer to store the read data
     * @param size Size of the data to read
     * @return true if reading was successful, false otherwise
     */
    public static native boolean readMemory(long address, byte[] buffer, int size);
    
    /**
     * Write memory to a specific address
     * 
     * @param address Address to write to
     * @param buffer Buffer containing the data to write
     * @param size Size of the data to write
     * @return true if writing was successful, false otherwise
     */
    public static native boolean writeMemory(long address, byte[] buffer, int size);
    
    /**
     * Find a pattern in memory
     * 
     * @param pattern Pattern to search for
     * @param moduleName Name of the module to search in
     * @return Address where the pattern was found, or 0 if not found
     */
    public static native long findPattern(String pattern, String moduleName);
    
    /**
     * Get the base address of a module
     * 
     * @param moduleName Name of the module
     * @return Base address of the module, or 0 if not found
     */
    public static native long getModuleBase(String moduleName);
    
    /**
     * Get the size of a module
     * 
     * @param moduleName Name of the module
     * @return Size of the module, or 0 if not found
     */
    public static native long getModuleSize(String moduleName);
}
