package com.bearmod.core.hooks;

/**
 * Enum for hook types
 */
public enum HookType {
    /**
     * Replace the original function with a new implementation
     */
    REPLACE,
    
    /**
     * Execute code before the original function
     */
    BEFORE,
    
    /**
     * Execute code after the original function
     */
    AFTER
}
