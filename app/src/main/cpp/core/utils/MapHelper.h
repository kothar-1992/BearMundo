#pragma once

#include <jni.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <android/log.h>

// Simple Vector3 class for positions
struct Vector3 {
    float x, y, z;
    
    Vector3() : x(0), y(0), z(0) {}
    Vector3(float _x, float _y, float _z) : x(_x), y(_y), z(_z) {}
    
    float Distance(const Vector3& other) const {
        float dx = x - other.x;
        float dy = y - other.y;
        float dz = z - other.z;
        return sqrt(dx*dx + dy*dy + dz*dz);
    }
};

// Simple Vector2 class for screen positions
struct Vector2 {
    float x, y;
    
    Vector2() : x(0), y(0) {}
    Vector2(float _x, float _y) : x(_x), y(_y) {}
};

// Item type enum
enum class ItemType {
    WEAPON,
    AMMO,
    ATTACHMENT,
    ARMOR,
    HELMET,
    BACKPACK,
    HEALTH,
    BOOST,
    THROWABLE,
    SCOPE,
    VEHICLE,
    OTHER
};

// Item class to represent game items
class Item {
public:
    int id;
    std::string name;
    ItemType type;
    Vector3 position;
    float distance;
    
    Item() : id(0), type(ItemType::OTHER), distance(0) {}
    
    Item(int _id, const std::string& _name, ItemType _type, const Vector3& _pos)
        : id(_id), name(_name), type(_type), position(_pos), distance(0) {}
};

// Player class to represent game players
class Player {
public:
    int id;
    std::string name;
    Vector3 position;
    float health;
    float distance;
    bool isBot;
    bool isTeammate;
    
    Player() : id(0), health(0), distance(0), isBot(false), isTeammate(false) {}
    
    Player(int _id, const std::string& _name, const Vector3& _pos, float _health, bool _isBot, bool _isTeammate)
        : id(_id), name(_name), position(_pos), health(_health), distance(0), isBot(_isBot), isTeammate(_isTeammate) {}
};

// MapHelper class to handle game mapping functionality
class MapHelper {
private:
    // Screen dimensions
    int screenWidth;
    int screenHeight;
    
    // Local player position
    Vector3 localPlayerPosition;
    
    // Lists of items and players
    std::vector<Item> items;
    std::vector<Player> players;
    
    // Item configuration (which items to show)
    std::unordered_map<int, bool> itemConfig;
    
    // Log tag
    static constexpr const char* LOG_TAG = "MapHelper";
    
public:
    MapHelper();
    ~MapHelper();
    
    // Initialize the helper
    void Initialize(int width, int height);
    
    // Update local player position
    void UpdateLocalPlayerPosition(float x, float y, float z);
    
    // Add an item to the map
    void AddItem(int id, const std::string& name, ItemType type, float x, float y, float z);
    
    // Add a player to the map
    void AddPlayer(int id, const std::string& name, float x, float y, float z, float health, bool isBot, bool isTeammate);
    
    // Clear all items and players
    void Clear();
    
    // Get items within a certain distance
    std::vector<Item> GetItemsInRange(float maxDistance);
    
    // Get players within a certain distance
    std::vector<Player> GetPlayersInRange(float maxDistance);
    
    // Convert world position to screen position
    Vector2 WorldToScreen(const Vector3& worldPos);
    
    // Set item configuration
    void SetItemConfig(int itemId, bool enabled);
    
    // Check if an item is enabled
    bool IsItemEnabled(int itemId);
    
    // Get screen dimensions
    int GetScreenWidth() const { return screenWidth; }
    int GetScreenHeight() const { return screenHeight; }
    
    // JNI methods
    static void RegisterNatives(JNIEnv* env);
    
private:
    // Calculate distances for all items and players
    void CalculateDistances();
    
    // JNI callback methods
    static void JNI_Initialize(JNIEnv* env, jclass clazz, jint width, jint height);
    static void JNI_UpdateLocalPlayerPosition(JNIEnv* env, jclass clazz, jfloat x, jfloat y, jfloat z);
    static void JNI_AddItem(JNIEnv* env, jclass clazz, jint id, jstring name, jint type, jfloat x, jfloat y, jfloat z);
    static void JNI_AddPlayer(JNIEnv* env, jclass clazz, jint id, jstring name, jfloat x, jfloat y, jfloat z, jfloat health, jboolean isBot, jboolean isTeammate);
    static void JNI_Clear(JNIEnv* env, jclass clazz);
    static jobjectArray JNI_GetItemsInRange(JNIEnv* env, jclass clazz, jfloat maxDistance);
    static jobjectArray JNI_GetPlayersInRange(JNIEnv* env, jclass clazz, jfloat maxDistance);
    static void JNI_SetItemConfig(JNIEnv* env, jclass clazz, jint itemId, jboolean enabled);
    static jboolean JNI_IsItemEnabled(JNIEnv* env, jclass clazz, jint itemId);
    
    // Singleton instance
    static MapHelper* instance;
};
