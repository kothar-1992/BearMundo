#pragma once

#include <string>

/**
 * @brief Logger class for debug output
 * 
 * This class provides a unified interface for logging
 * messages at different levels (debug, info, warning, error)
 */
class Logger {
public:
    /**
     * @brief Log levels
     */
    enum class Level {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    /**
     * @brief Initialize the logger
     * 
     * @param tag Tag to use for log messages
     * @param level Minimum log level to display
     */
    static void initialize(const std::string& tag, Level level = Level::INFO);

    /**
     * @brief Set the minimum log level
     * 
     * @param level Minimum log level to display
     */
    static void setLevel(Level level);

    /**
     * @brief Log a debug message
     * 
     * @param format Format string
     * @param ... Format arguments
     */
    static void debug(const char* format, ...);

    /**
     * @brief Log an info message
     * 
     * @param format Format string
     * @param ... Format arguments
     */
    static void info(const char* format, ...);

    /**
     * @brief Log a warning message
     * 
     * @param format Format string
     * @param ... Format arguments
     */
    static void warning(const char* format, ...);

    /**
     * @brief Log an error message
     * 
     * @param format Format string
     * @param ... Format arguments
     */
    static void error(const char* format, ...);

private:
    static std::string tag;
    static Level level;
    static bool initialized;
};
