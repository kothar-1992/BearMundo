#pragma once

#include <cstdint>
#include <vector>
#include <string>

/**
 * @brief Manager class for memory operations
 * 
 * This class provides a unified interface for memory operations
 * such as reading, writing, and pattern scanning
 */
class MemoryManager {
public:
    /**
     * @brief Initialize the memory manager
     * 
     * @return true if initialization was successful
     * @return false if initialization failed
     */
    static bool initialize();

    /**
     * @brief Read memory from a specific address
     * 
     * @param address Address to read from
     * @param buffer Buffer to store the read data
     * @param size Size of the data to read
     * @return true if reading was successful
     * @return false if reading failed
     */
    static bool readMemory(uintptr_t address, void* buffer, size_t size);

    /**
     * @brief Write memory to a specific address
     * 
     * @param address Address to write to
     * @param buffer Buffer containing the data to write
     * @param size Size of the data to write
     * @return true if writing was successful
     * @return false if writing failed
     */
    static bool writeMemory(uintptr_t address, const void* buffer, size_t size);

    /**
     * @brief Find a pattern in memory
     * 
     * @param pattern Pattern to search for (e.g., "48 8B 05 ? ? ? ? 48 8B 08")
     * @param start Start address for the search
     * @param end End address for the search
     * @return Address where the pattern was found, or 0 if not found
     */
    static uintptr_t findPattern(const std::string& pattern, uintptr_t start, uintptr_t end);

    /**
     * @brief Find a pattern in a specific module
     * 
     * @param pattern Pattern to search for
     * @param moduleName Name of the module to search in
     * @return Address where the pattern was found, or 0 if not found
     */
    static uintptr_t findPatternInModule(const std::string& pattern, const std::string& moduleName);

    /**
     * @brief Get the base address of a module
     * 
     * @param moduleName Name of the module
     * @return Base address of the module, or 0 if not found
     */
    static uintptr_t getModuleBase(const std::string& moduleName);

    /**
     * @brief Get the size of a module
     * 
     * @param moduleName Name of the module
     * @return Size of the module, or 0 if not found
     */
    static size_t getModuleSize(const std::string& moduleName);

private:
    static bool initialized;
};
