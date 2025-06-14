#include "MapHelper.h"
#include <cmath>
#include <algorithm>

// Initialize static members
MapHelper* MapHelper::instance = nullptr;

MapHelper::MapHelper() : screenWidth(0), screenHeight(0) {
    instance = this;
}

MapHelper::~MapHelper() {
    if (instance == this) {
        instance = nullptr;
    }
}

void MapHelper::Initialize(int width, int height) {
    screenWidth = width;
    screenHeight = height;
    
    // Log initialization
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "MapHelper initialized with screen size: %dx%d", width, height);
}

void MapHelper::UpdateLocalPlayerPosition(float x, float y, float z) {
    localPlayerPosition = Vector3(x, y, z);
    
    // Recalculate distances when player position changes
    CalculateDistances();
}

void MapHelper::AddItem(int id, const std::string& name, ItemType type, float x, float y, float z) {
    // Create a new item
    Item item(id, name, type, Vector3(x, y, z));
    
    // Calculate distance from player
    item.distance = item.position.Distance(localPlayerPosition);
    
    // Add to items list
    items.push_back(item);
}

void MapHelper::AddPlayer(int id, const std::string& name, float x, float y, float z, float health, bool isBot, bool isTeammate) {
    // Create a new player
    Player player(id, name, Vector3(x, y, z), health, isBot, isTeammate);
    
    // Calculate distance from local player
    player.distance = player.position.Distance(localPlayerPosition);
    
    // Add to players list
    players.push_back(player);
}

void MapHelper::Clear() {
    // Clear items and players lists
    items.clear();
    players.clear();
}

std::vector<Item> MapHelper::GetItemsInRange(float maxDistance) {
    std::vector<Item> result;
    
    // Filter items by distance and configuration
    for (const auto& item : items) {
        if (item.distance <= maxDistance && IsItemEnabled(item.id)) {
            result.push_back(item);
        }
    }
    
    // Sort by distance (closest first)
    std::sort(result.begin(), result.end(), [](const Item& a, const Item& b) {
        return a.distance < b.distance;
    });
    
    return result;
}

std::vector<Player> MapHelper::GetPlayersInRange(float maxDistance) {
    std::vector<Player> result;
    
    // Filter players by distance
    for (const auto& player : players) {
        if (player.distance <= maxDistance) {
            result.push_back(player);
        }
    }
    
    // Sort by distance (closest first)
    std::sort(result.begin(), result.end(), [](const Player& a, const Player& b) {
        return a.distance < b.distance;
    });
    
    return result;
}

Vector2 MapHelper::WorldToScreen(const Vector3& worldPos) {
    // This is a simplified implementation
    // In a real game, you would use the game's projection matrix
    
    // Calculate direction vector from player to position
    Vector3 direction;
    direction.x = worldPos.x - localPlayerPosition.x;
    direction.y = worldPos.y - localPlayerPosition.y;
    direction.z = worldPos.z - localPlayerPosition.z;
    
    // Calculate distance in 2D plane
    float distance2D = sqrt(direction.x * direction.x + direction.y * direction.y);
    
    // Calculate angles
    float pitch = -atan2(direction.z, distance2D);
    float yaw = atan2(direction.y, direction.x);
    
    // Convert to screen coordinates (simplified)
    float screenX = screenWidth / 2 + (yaw * screenWidth / (2 * M_PI));
    float screenY = screenHeight / 2 - (pitch * screenHeight / M_PI);
    
    return Vector2(screenX, screenY);
}

void MapHelper::SetItemConfig(int itemId, bool enabled) {
    itemConfig[itemId] = enabled;
}

bool MapHelper::IsItemEnabled(int itemId) {
    // If item is not in config, default to enabled
    if (itemConfig.find(itemId) == itemConfig.end()) {
        return true;
    }
    
    return itemConfig[itemId];
}

void MapHelper::CalculateDistances() {
    // Update distances for all items
    for (auto& item : items) {
        item.distance = item.position.Distance(localPlayerPosition);
    }
    
    // Update distances for all players
    for (auto& player : players) {
        player.distance = player.position.Distance(localPlayerPosition);
    }
}

// JNI Methods
void MapHelper::RegisterNatives(JNIEnv* env) {
    // Find the MapHelper class
    jclass clazz = env->FindClass("com/bearmod/MapHelper");
    if (clazz == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find MapHelper class");
        return;
    }
    
    // Define native methods
    static const JNINativeMethod methods[] = {
        {"initialize", "(II)V", (void*)MapHelper::JNI_Initialize},
        {"updateLocalPlayerPosition", "(FFF)V", (void*)MapHelper::JNI_UpdateLocalPlayerPosition},
        {"addItem", "(ILjava/lang/String;IFFF)V", (void*)MapHelper::JNI_AddItem},
        {"addPlayer", "(ILjava/lang/String;FFFZZ)V", (void*)MapHelper::JNI_AddPlayer},
        {"clear", "()V", (void*)MapHelper::JNI_Clear},
        {"getItemsInRange", "(F)[Lcom/bearmod/Item;", (void*)MapHelper::JNI_GetItemsInRange},
        {"getPlayersInRange", "(F)[Lcom/bearmod/Player;", (void*)MapHelper::JNI_GetPlayersInRange},
        {"setItemConfig", "(IZ)V", (void*)MapHelper::JNI_SetItemConfig},
        {"isItemEnabled", "(I)Z", (void*)MapHelper::JNI_IsItemEnabled}
    };
    
    // Register native methods
    env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0]));
    
    // Check for exceptions
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to register native methods");
    }
}

// JNI callback implementations
void MapHelper::JNI_Initialize(JNIEnv* env, jclass clazz, jint width, jint height) {
    if (instance == nullptr) {
        instance = new MapHelper();
    }
    
    instance->Initialize(width, height);
}

void MapHelper::JNI_UpdateLocalPlayerPosition(JNIEnv* env, jclass clazz, jfloat x, jfloat y, jfloat z) {
    if (instance != nullptr) {
        instance->UpdateLocalPlayerPosition(x, y, z);
    }
}

void MapHelper::JNI_AddItem(JNIEnv* env, jclass clazz, jint id, jstring name, jint type, jfloat x, jfloat y, jfloat z) {
    if (instance != nullptr) {
        // Convert Java string to C++ string
        const char* nameChars = env->GetStringUTFChars(name, nullptr);
        std::string nameStr(nameChars);
        env->ReleaseStringUTFChars(name, nameChars);
        
        // Add item
        instance->AddItem(id, nameStr, static_cast<ItemType>(type), x, y, z);
    }
}

void MapHelper::JNI_AddPlayer(JNIEnv* env, jclass clazz, jint id, jstring name, jfloat x, jfloat y, jfloat z, jfloat health, jboolean isBot, jboolean isTeammate) {
    if (instance != nullptr) {
        // Convert Java string to C++ string
        const char* nameChars = env->GetStringUTFChars(name, nullptr);
        std::string nameStr(nameChars);
        env->ReleaseStringUTFChars(name, nameChars);
        
        // Add player
        instance->AddPlayer(id, nameStr, x, y, z, health, isBot == JNI_TRUE, isTeammate == JNI_TRUE);
    }
}

void MapHelper::JNI_Clear(JNIEnv* env, jclass clazz) {
    if (instance != nullptr) {
        instance->Clear();
    }
}

jobjectArray MapHelper::JNI_GetItemsInRange(JNIEnv* env, jclass clazz, jfloat maxDistance) {
    if (instance == nullptr) {
        return nullptr;
    }
    
    // Get items in range
    std::vector<Item> items = instance->GetItemsInRange(maxDistance);
    
    // Find Item class
    jclass itemClass = env->FindClass("com/bearmod/Item");
    if (itemClass == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find Item class");
        return nullptr;
    }
    
    // Create array of Item objects
    jobjectArray result = env->NewObjectArray(items.size(), itemClass, nullptr);
    
    // Find Item constructor
    jmethodID constructor = env->GetMethodID(itemClass, "<init>", "(ILjava/lang/String;IFFFLcom/bearmod/Vector3;F)V");
    if (constructor == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find Item constructor");
        return nullptr;
    }
    
    // Find Vector3 class
    jclass vector3Class = env->FindClass("com/bearmod/Vector3");
    if (vector3Class == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find Vector3 class");
        return nullptr;
    }
    
    // Find Vector3 constructor
    jmethodID vector3Constructor = env->GetMethodID(vector3Class, "<init>", "(FFF)V");
    if (vector3Constructor == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find Vector3 constructor");
        return nullptr;
    }
    
    // Fill array with Item objects
    for (size_t i = 0; i < items.size(); i++) {
        const Item& item = items[i];
        
        // Create Vector3 object for position
        jobject position = env->NewObject(vector3Class, vector3Constructor, item.position.x, item.position.y, item.position.z);
        
        // Create Item object
        jstring itemName = env->NewStringUTF(item.name.c_str());
        jobject itemObject = env->NewObject(itemClass, constructor, item.id, itemName, static_cast<jint>(item.type), 
                                           item.position.x, item.position.y, item.position.z, position, item.distance);
        
        // Add to array
        env->SetObjectArrayElement(result, i, itemObject);
        
        // Clean up local references
        env->DeleteLocalRef(itemName);
        env->DeleteLocalRef(position);
        env->DeleteLocalRef(itemObject);
    }
    
    return result;
}

jobjectArray MapHelper::JNI_GetPlayersInRange(JNIEnv* env, jclass clazz, jfloat maxDistance) {
    if (instance == nullptr) {
        return nullptr;
    }
    
    // Get players in range
    std::vector<Player> players = instance->GetPlayersInRange(maxDistance);
    
    // Find Player class
    jclass playerClass = env->FindClass("com/bearmod/Player");
    if (playerClass == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find Player class");
        return nullptr;
    }
    
    // Create array of Player objects
    jobjectArray result = env->NewObjectArray(players.size(), playerClass, nullptr);
    
    // Find Player constructor
    jmethodID constructor = env->GetMethodID(playerClass, "<init>", "(ILjava/lang/String;FFFLcom/bearmod/Vector3;FZZ)V");
    if (constructor == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find Player constructor");
        return nullptr;
    }
    
    // Find Vector3 class
    jclass vector3Class = env->FindClass("com/bearmod/Vector3");
    if (vector3Class == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find Vector3 class");
        return nullptr;
    }
    
    // Find Vector3 constructor
    jmethodID vector3Constructor = env->GetMethodID(vector3Class, "<init>", "(FFF)V");
    if (vector3Constructor == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to find Vector3 constructor");
        return nullptr;
    }
    
    // Fill array with Player objects
    for (size_t i = 0; i < players.size(); i++) {
        const Player& player = players[i];
        
        // Create Vector3 object for position
        jobject position = env->NewObject(vector3Class, vector3Constructor, player.position.x, player.position.y, player.position.z);
        
        // Create Player object
        jstring playerName = env->NewStringUTF(player.name.c_str());
        jobject playerObject = env->NewObject(playerClass, constructor, player.id, playerName, 
                                             player.position.x, player.position.y, player.position.z, 
                                             position, player.health, player.isBot, player.isTeammate);
        
        // Add to array
        env->SetObjectArrayElement(result, i, playerObject);
        
        // Clean up local references
        env->DeleteLocalRef(playerName);
        env->DeleteLocalRef(position);
        env->DeleteLocalRef(playerObject);
    }
    
    return result;
}

void MapHelper::JNI_SetItemConfig(JNIEnv* env, jclass clazz, jint itemId, jboolean enabled) {
    if (instance != nullptr) {
        instance->SetItemConfig(itemId, enabled == JNI_TRUE);
    }
}

jboolean MapHelper::JNI_IsItemEnabled(JNIEnv* env, jclass clazz, jint itemId) {
    if (instance != nullptr) {
        return instance->IsItemEnabled(itemId) ? JNI_TRUE : JNI_FALSE;
    }
    return JNI_FALSE;
}
