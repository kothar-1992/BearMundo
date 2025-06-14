#pragma once

/**
 * MinimalSDK.h
 * 
 * A minimal wrapper around the PUBGM SDK to isolate its functionality
 * and provide a cleaner interface for the rest of the application.
 */

#include <string>
#include <vector>

// Forward declarations to avoid including SDK headers directly
struct Vector3;
struct Rotator;

namespace MinimalSDK {

    /**
     * Initialize the SDK
     * @return true if initialization was successful
     */
    bool Initialize();

    /**
     * Clean up SDK resources
     */
    void Cleanup();

    /**
     * Check if the SDK is available and initialized
     * @return true if SDK is available and initialized
     */
    bool IsAvailable();

    /**
     * Get an object by its name
     * @param name The name of the object to find
     * @return Pointer to the object, or nullptr if not found
     */
    void* GetObjectByName(const char* name);

    /**
     * Get an object by its ID
     * @param id The ID of the object to find
     * @return Pointer to the object, or nullptr if not found
     */
    void* GetObjectById(int id);

    /**
     * Player-related functions
     */
    namespace Player {
        /**
         * Get the local player
         * @return Pointer to the local player, or nullptr if not found
         */
        void* GetLocalPlayer();

        /**
         * Get a player's position
         * @param player Pointer to the player
         * @param outPosition Output parameter for the position
         * @return true if successful
         */
        bool GetPosition(void* player, Vector3& outPosition);

        /**
         * Get a player's rotation
         * @param player Pointer to the player
         * @param outRotation Output parameter for the rotation
         * @return true if successful
         */
        bool GetRotation(void* player, Rotator& outRotation);

        /**
         * Get a player's health
         * @param player Pointer to the player
         * @return The player's health (0-100), or -1 if failed
         */
        float GetHealth(void* player);

        /**
         * Check if a player is visible
         * @param player Pointer to the player
         * @return true if the player is visible
         */
        bool IsVisible(void* player);

        /**
         * Get a player's name
         * @param player Pointer to the player
         * @return The player's name, or empty string if failed
         */
        std::string GetName(void* player);

        /**
         * Get a player's team ID
         * @param player Pointer to the player
         * @return The player's team ID, or -1 if failed
         */
        int GetTeamId(void* player);

        /**
         * Check if a player is a bot
         * @param player Pointer to the player
         * @return true if the player is a bot
         */
        bool IsBot(void* player);
    }

    /**
     * Item-related functions
     */
    namespace Item {
        /**
         * Get an item's position
         * @param item Pointer to the item
         * @param outPosition Output parameter for the position
         * @return true if successful
         */
        bool GetPosition(void* item, Vector3& outPosition);

        /**
         * Get an item's name
         * @param item Pointer to the item
         * @return The item's name, or empty string if failed
         */
        std::string GetName(void* item);

        /**
         * Get an item's ID
         * @param item Pointer to the item
         * @return The item's ID, or -1 if failed
         */
        int GetId(void* item);

        /**
         * Get an item's type
         * @param item Pointer to the item
         * @return The item's type, or -1 if failed
         */
        int GetType(void* item);
    }

    /**
     * World-related functions
     */
    namespace World {
        /**
         * Get all players in the world
         * @return Vector of pointers to players
         */
        std::vector<void*> GetAllPlayers();

        /**
         * Get all items in the world
         * @return Vector of pointers to items
         */
        std::vector<void*> GetAllItems();

        /**
         * Get the current match state
         * @return The current match state as a string
         */
        std::string GetMatchState();

        /**
         * Get the safe zone position
         * @param outPosition Output parameter for the position
         * @return true if successful
         */
        bool GetSafeZonePosition(Vector3& outPosition);

        /**
         * Get the safe zone radius
         * @return The safe zone radius, or -1 if failed
         */
        float GetSafeZoneRadius();
    }

    /**
     * Utility functions
     */
    namespace Utility {
        /**
         * Convert a world position to screen position
         * @param worldPosition The position in world space
         * @param outScreenX Output parameter for screen X coordinate
         * @param outScreenY Output parameter for screen Y coordinate
         * @return true if the position is on screen
         */
        bool WorldToScreen(const Vector3& worldPosition, float& outScreenX, float& outScreenY);

        /**
         * Calculate the distance between two positions
         * @param pos1 First position
         * @param pos2 Second position
         * @return The distance in game units
         */
        float Distance(const Vector3& pos1, const Vector3& pos2);

        /**
         * Calculate the 2D distance between two positions (ignoring height)
         * @param pos1 First position
         * @param pos2 Second position
         * @return The 2D distance in game units
         */
        float Distance2D(const Vector3& pos1, const Vector3& pos2);
    }
}

// Common structures used by the SDK wrapper
struct Vector3 {
    float X;
    float Y;
    float Z;

    Vector3() : X(0), Y(0), Z(0) {}
    Vector3(float x, float y, float z) : X(x), Y(y), Z(z) {}
};

struct Rotator {
    float Pitch;
    float Yaw;
    float Roll;

    Rotator() : Pitch(0), Yaw(0), Roll(0) {}
    Rotator(float pitch, float yaw, float roll) : Pitch(pitch), Yaw(yaw), Roll(roll) {}
};
