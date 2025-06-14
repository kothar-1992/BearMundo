#pragma once

#include <cstdint>
#include <string>

/**
 * @brief Manager class for hooking functions
 * 
 * This class provides a unified interface for hooking functions
 * using various hooking libraries (Dobby, Substrate, etc.)
 */
class HookManager {
public:
    /**
     * @brief Initialize the hook manager
     * 
     * @return true if initialization was successful
     * @return false if initialization failed
     */
    static bool initialize();

    /**
     * @brief Hook a function
     * 
     * @param target Pointer to the target function
     * @param replacement Pointer to the replacement function
     * @param original Pointer to store the original function
     * @return true if hooking was successful
     * @return false if hooking failed
     */
    static bool hookFunction(void* target, void* replacement, void** original);

    /**
     * @brief Hook a function by name
     * 
     * @param libraryName Name of the library containing the function
     * @param functionName Name of the function to hook
     * @param replacement Pointer to the replacement function
     * @param original Pointer to store the original function
     * @return true if hooking was successful
     * @return false if hooking failed
     */
    static bool hookFunctionByName(const std::string& libraryName, 
                                  const std::string& functionName,
                                  void* replacement,
                                  void** original);

    /**
     * @brief Unhook a function
     * 
     * @param target Pointer to the target function
     * @return true if unhooking was successful
     * @return false if unhooking failed
     */
    static bool unhookFunction(void* target);

private:
    static bool initialized;
};
