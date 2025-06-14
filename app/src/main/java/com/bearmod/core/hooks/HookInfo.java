package com.bearmod.core.hooks;

/**
 * Class for storing information about a hook
 */
public class HookInfo {
    private final String libraryName;
    private final String functionName;
    private final HookType hookType;
    private final long timestamp;
    
    /**
     * Constructor
     * 
     * @param libraryName Name of the library containing the function
     * @param functionName Name of the function
     * @param hookType Type of hook
     */
    public HookInfo(String libraryName, String functionName, HookType hookType) {
        this.libraryName = libraryName;
        this.functionName = functionName;
        this.hookType = hookType;
        this.timestamp = System.currentTimeMillis();
    }
    
    /**
     * Get the library name
     * 
     * @return Library name
     */
    public String getLibraryName() {
        return libraryName;
    }
    
    /**
     * Get the function name
     * 
     * @return Function name
     */
    public String getFunctionName() {
        return functionName;
    }
    
    /**
     * Get the hook type
     * 
     * @return Hook type
     */
    public HookType getHookType() {
        return hookType;
    }
    
    /**
     * Get the timestamp when the hook was created
     * 
     * @return Timestamp in milliseconds
     */
    public long getTimestamp() {
        return timestamp;
    }
    
    @Override
    public String toString() {
        return "HookInfo{" +
                "libraryName='" + libraryName + '\'' +
                ", functionName='" + functionName + '\'' +
                ", hookType=" + hookType +
                ", timestamp=" + timestamp +
                '}';
    }
}
