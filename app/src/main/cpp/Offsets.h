#pragma once

// Offset definitions for PUBGM GL-64bit
// Last updated: 2023-12-15

namespace Offsets {
    // Global object arrays
    constexpr uintptr_t GNames = 0x8E3B1A0;         // FName::GNames
    constexpr uintptr_t GUObjects = 0x8F7F2A0;      // UObject::GUObjectArray
    
    // UWorld related
    constexpr uintptr_t UWorld = 0x8F9F2A0;         // Main UWorld pointer
    constexpr uintptr_t GameInstance = 0x180;       // UWorld->GameInstance offset
    constexpr uintptr_t LocalPlayers = 0x38;        // UGameInstance->LocalPlayers offset
    constexpr uintptr_t PlayerController = 0x30;    // UPlayer->PlayerController offset
    constexpr uintptr_t AcknowledgedPawn = 0x460;   // APlayerController->AcknowledgedPawn offset
    
    // Actor related
    constexpr uintptr_t ActorArray = 0x98;          // ULevel->Actors offset
    constexpr uintptr_t ActorCount = 0xA0;          // ULevel->ActorsCount offset
    constexpr uintptr_t RootComponent = 0x230;      // AActor->RootComponent offset
    constexpr uintptr_t Position = 0x1A0;           // USceneComponent->Position offset
    
    // Player related
    constexpr uintptr_t PlayerState = 0x3F0;        // APawn->PlayerState offset
    constexpr uintptr_t TeamID = 0x8A8;             // APlayerState->TeamID offset
    constexpr uintptr_t Health = 0xBC0;             // APawn->Health offset
    constexpr uintptr_t HealthMax = 0xBC4;          // APawn->HealthMax offset
    
    // Item related
    constexpr uintptr_t ItemID = 0x40C;             // AItem->ItemID offset
    constexpr uintptr_t ItemName = 0x5F8;           // AItem->ItemName offset
    constexpr uintptr_t ItemType = 0x54;            // AItem->ItemType offset
    
    // Function offsets
    constexpr uintptr_t GetBoneMatrix = 0x7A23A10;  // Mesh->GetBoneMatrix function
    constexpr uintptr_t ProjectWorldToScreen = 0x7B12C40; // PlayerController->ProjectWorldToScreen function
    
    // Add more offsets as needed
}

// Helper functions to use with offsets
namespace OffsetHelpers {
    // Read memory at base + offset
    template<typename T>
    inline T Read(uintptr_t base, uintptr_t offset) {
        if (base == 0) return T{};
        return *(T*)(base + offset);
    }
    
    // Write memory at base + offset
    template<typename T>
    inline void Write(uintptr_t base, uintptr_t offset, T value) {
        if (base == 0) return;
        *(T*)(base + offset) = value;
    }
    
    // Get UWorld instance
    inline uintptr_t GetUWorld() {
        return *(uintptr_t*)(Offsets::UWorld);
    }
    
    // Get local player pawn
    inline uintptr_t GetLocalPlayerPawn() {
        uintptr_t uworld = GetUWorld();
        if (!uworld) return 0;
        
        uintptr_t game_instance = Read<uintptr_t>(uworld, Offsets::GameInstance);
        if (!game_instance) return 0;
        
        uintptr_t local_players = Read<uintptr_t>(game_instance, Offsets::LocalPlayers);
        if (!local_players) return 0;
        
        uintptr_t local_player = Read<uintptr_t>(local_players, 0);
        if (!local_player) return 0;
        
        uintptr_t player_controller = Read<uintptr_t>(local_player, Offsets::PlayerController);
        if (!player_controller) return 0;
        
        return Read<uintptr_t>(player_controller, Offsets::AcknowledgedPawn);
    }
    
    // Get actor position
    inline Vector3 GetActorPosition(uintptr_t actor) {
        if (!actor) return Vector3{0, 0, 0};
        
        uintptr_t root_component = Read<uintptr_t>(actor, Offsets::RootComponent);
        if (!root_component) return Vector3{0, 0, 0};
        
        return Read<Vector3>(root_component, Offsets::Position);
    }
    
    // Check if actor is player
    inline bool IsPlayer(uintptr_t actor) {
        // Implementation depends on how you identify players
        // This is a simplified example
        if (!actor) return false;
        
        // Check if actor has health component
        float health = Read<float>(actor, Offsets::Health);
        return health > 0 && health <= 100;
    }
    
    // Get player health
    inline float GetPlayerHealth(uintptr_t player) {
        if (!player) return 0;
        return Read<float>(player, Offsets::Health);
    }
    
    // Get player team ID
    inline int GetPlayerTeamID(uintptr_t player) {
        if (!player) return -1;
        
        uintptr_t player_state = Read<uintptr_t>(player, Offsets::PlayerState);
        if (!player_state) return -1;
        
        return Read<int>(player_state, Offsets::TeamID);
    }
}
