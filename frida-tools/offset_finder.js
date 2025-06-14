/**
 * Offset Finder - Frida script for finding and validating memory offsets
 * 
 * This script helps identify and validate memory offsets for game objects,
 * which is particularly useful for SDK development and reverse engineering.
 */

// Configuration
const config = {
    debug: true,
    targetModule: "libbearmod.so",
    scanForStrings: true,
    scanForPointers: true,
    validateOffsets: true,
    logLevel: 'info'  // 'debug', 'info', 'warn', 'error'
};

// Known offsets to validate
const knownOffsets = {
    // UWorld related
    GNames: 0x8E3B1A0,         // FName::GNames
    GUObjects: 0x8F7F2A0,      // UObject::GUObjectArray
    UWorld: 0x8F9F2A0,         // Main UWorld pointer
    GameInstance: 0x180,       // UWorld->GameInstance offset
    LocalPlayers: 0x38,        // UGameInstance->LocalPlayers offset
    PlayerController: 0x30,    // UPlayer->PlayerController offset
    AcknowledgedPawn: 0x460,   // APlayerController->AcknowledgedPawn offset
    
    // Actor related
    ActorArray: 0x98,          // ULevel->Actors offset
    ActorCount: 0xA0,          // ULevel->ActorsCount offset
    RootComponent: 0x230,      // AActor->RootComponent offset
    Position: 0x1A0,           // USceneComponent->Position offset
    
    // Player related
    PlayerState: 0x3F0,        // APawn->PlayerState offset
    TeamID: 0x8A8,             // APlayerState->TeamID offset
    Health: 0xBC0,             // APawn->Health offset
    HealthMax: 0xBC4           // APawn->HealthMax offset
};

// Logging utilities
const Log = {
    d: function(message) {
        if (config.logLevel === 'debug' || config.debug) {
            console.log(`[D] ${message}`);
        }
    },
    i: function(message) {
        if (config.logLevel === 'debug' || config.logLevel === 'info' || config.debug) {
            console.log(`[I] ${message}`);
        }
    },
    w: function(message) {
        if (config.logLevel === 'debug' || config.logLevel === 'info' || config.logLevel === 'warn' || config.debug) {
            console.log(`[W] ${message}`);
        }
    },
    e: function(message) {
        console.log(`[E] ${message}`);
    },
    highlight: function(message) {
        console.log(`\n[*] ======== ${message} ========\n`);
    },
    offset: function(name, address, value, valid) {
        const status = valid ? "✓" : "✗";
        console.log(`[OFFSET] ${status} ${name}: 0x${address.toString(16).toUpperCase()} = ${value}`);
    }
};

// Utility functions
const Utils = {
    // Read memory safely
    readMemory: function(address, type) {
        try {
            switch (type) {
                case 'pointer':
                    return Memory.readPointer(address);
                case 'int':
                    return Memory.readInt(address);
                case 'uint':
                    return Memory.readUInt(address);
                case 'long':
                    return Memory.readLong(address);
                case 'ulong':
                    return Memory.readULong(address);
                case 'float':
                    return Memory.readFloat(address);
                case 'double':
                    return Memory.readDouble(address);
                case 'byte':
                    return Memory.readS8(address);
                case 'ubyte':
                    return Memory.readU8(address);
                case 'short':
                    return Memory.readS16(address);
                case 'ushort':
                    return Memory.readU16(address);
                case 'string':
                    return Memory.readUtf8String(address);
                default:
                    return null;
            }
        } catch (e) {
            return null;
        }
    },
    
    // Check if address is valid
    isValidAddress: function(address) {
        if (address === null || address === undefined) {
            return false;
        }
        
        try {
            const value = Memory.readU8(address);
            return true;
        } catch (e) {
            return false;
        }
    },
    
    // Check if value looks like a pointer
    isLikelyPointer: function(value) {
        // On 64-bit systems, pointers are usually in a specific range
        if (Process.pointerSize === 8) {
            // Check if the value is in a reasonable range for a pointer
            // This is a heuristic and may need adjustment
            return value > 0x100000000 && value < 0x7FFFFFFFFFFF;
        } else {
            // On 32-bit systems, pointers are usually above 0x10000
            return value > 0x10000 && value < 0xFFFFFFFF;
        }
    },
    
    // Get module base address
    getModuleBase: function(moduleName) {
        const module = Process.findModuleByName(moduleName);
        return module ? module.base : null;
    },
    
    // Convert address to module offset
    addressToOffset: function(address, moduleName) {
        const base = this.getModuleBase(moduleName);
        if (base && address) {
            return address.sub(base);
        }
        return null;
    },
    
    // Convert offset to absolute address
    offsetToAddress: function(offset, moduleName) {
        const base = this.getModuleBase(moduleName);
        if (base) {
            return base.add(offset);
        }
        return null;
    }
};

// Main initialization
function initialize() {
    Log.highlight("Offset Finder Starting");
    
    // Find target module
    const targetModule = Process.findModuleByName(config.targetModule);
    if (!targetModule) {
        Log.e(`Target module ${config.targetModule} not found`);
        return;
    }
    
    Log.i(`Found target module ${config.targetModule} at ${targetModule.base}`);
    
    // Validate known offsets
    if (config.validateOffsets) {
        validateKnownOffsets(targetModule);
    }
    
    // Scan for strings
    if (config.scanForStrings) {
        scanForStrings(targetModule);
    }
    
    // Scan for pointers
    if (config.scanForPointers) {
        scanForPointers(targetModule);
    }
    
    Log.highlight("Offset Finder Initialized");
}

// Validate known offsets
function validateKnownOffsets(targetModule) {
    Log.highlight("Validating Known Offsets");
    
    // Global offsets
    validateGlobalOffsets(targetModule);
    
    // Get UWorld instance
    const uWorldPtr = getUWorldInstance(targetModule);
    if (uWorldPtr) {
        // Validate UWorld-related offsets
        validateUWorldOffsets(uWorldPtr);
        
        // Get local player
        const localPlayerPtr = getLocalPlayer(uWorldPtr);
        if (localPlayerPtr) {
            // Validate player-related offsets
            validatePlayerOffsets(localPlayerPtr);
        }
    }
    
    Log.highlight("Offset Validation Complete");
}

// Validate global offsets
function validateGlobalOffsets(targetModule) {
    Log.i("Validating global offsets");
    
    // Validate GNames
    const gNamesPtr = Utils.offsetToAddress(knownOffsets.GNames, config.targetModule);
    if (gNamesPtr) {
        const gNamesValue = Utils.readMemory(gNamesPtr, 'pointer');
        const isValid = Utils.isValidAddress(gNamesValue) && Utils.isLikelyPointer(gNamesValue);
        Log.offset("GNames", gNamesPtr, gNamesValue, isValid);
    }
    
    // Validate GUObjects
    const gUObjectsPtr = Utils.offsetToAddress(knownOffsets.GUObjects, config.targetModule);
    if (gUObjectsPtr) {
        const gUObjectsValue = Utils.readMemory(gUObjectsPtr, 'pointer');
        const isValid = Utils.isValidAddress(gUObjectsValue) && Utils.isLikelyPointer(gUObjectsValue);
        Log.offset("GUObjects", gUObjectsPtr, gUObjectsValue, isValid);
    }
    
    // Validate UWorld
    const uWorldPtr = Utils.offsetToAddress(knownOffsets.UWorld, config.targetModule);
    if (uWorldPtr) {
        const uWorldValue = Utils.readMemory(uWorldPtr, 'pointer');
        const isValid = Utils.isValidAddress(uWorldValue) && Utils.isLikelyPointer(uWorldValue);
        Log.offset("UWorld", uWorldPtr, uWorldValue, isValid);
    }
}

// Get UWorld instance
function getUWorldInstance(targetModule) {
    Log.i("Getting UWorld instance");
    
    const uWorldPtr = Utils.offsetToAddress(knownOffsets.UWorld, config.targetModule);
    if (!uWorldPtr) {
        Log.e("Failed to get UWorld pointer");
        return null;
    }
    
    const uWorldValue = Utils.readMemory(uWorldPtr, 'pointer');
    if (!Utils.isValidAddress(uWorldValue)) {
        Log.e("Invalid UWorld pointer");
        return null;
    }
    
    Log.i(`UWorld instance found at ${uWorldValue}`);
    return uWorldValue;
}

// Validate UWorld-related offsets
function validateUWorldOffsets(uWorldPtr) {
    Log.i("Validating UWorld-related offsets");
    
    // Validate GameInstance
    const gameInstancePtr = uWorldPtr.add(knownOffsets.GameInstance);
    const gameInstanceValue = Utils.readMemory(gameInstancePtr, 'pointer');
    const isGameInstanceValid = Utils.isValidAddress(gameInstanceValue) && Utils.isLikelyPointer(gameInstanceValue);
    Log.offset("GameInstance", gameInstancePtr, gameInstanceValue, isGameInstanceValid);
    
    if (isGameInstanceValid) {
        // Validate LocalPlayers
        const localPlayersPtr = gameInstanceValue.add(knownOffsets.LocalPlayers);
        const localPlayersValue = Utils.readMemory(localPlayersPtr, 'pointer');
        const isLocalPlayersValid = Utils.isValidAddress(localPlayersValue) && Utils.isLikelyPointer(localPlayersValue);
        Log.offset("LocalPlayers", localPlayersPtr, localPlayersValue, isLocalPlayersValid);
    }
}

// Get local player
function getLocalPlayer(uWorldPtr) {
    Log.i("Getting local player");
    
    // Get GameInstance
    const gameInstancePtr = uWorldPtr.add(knownOffsets.GameInstance);
    const gameInstanceValue = Utils.readMemory(gameInstancePtr, 'pointer');
    if (!Utils.isValidAddress(gameInstanceValue)) {
        Log.e("Invalid GameInstance pointer");
        return null;
    }
    
    // Get LocalPlayers
    const localPlayersPtr = gameInstanceValue.add(knownOffsets.LocalPlayers);
    const localPlayersValue = Utils.readMemory(localPlayersPtr, 'pointer');
    if (!Utils.isValidAddress(localPlayersValue)) {
        Log.e("Invalid LocalPlayers pointer");
        return null;
    }
    
    // Get first LocalPlayer
    const localPlayerPtr = Utils.readMemory(localPlayersValue, 'pointer');
    if (!Utils.isValidAddress(localPlayerPtr)) {
        Log.e("Invalid LocalPlayer pointer");
        return null;
    }
    
    // Get PlayerController
    const playerControllerPtr = localPlayerPtr.add(knownOffsets.PlayerController);
    const playerControllerValue = Utils.readMemory(playerControllerPtr, 'pointer');
    if (!Utils.isValidAddress(playerControllerValue)) {
        Log.e("Invalid PlayerController pointer");
        return null;
    }
    
    // Get AcknowledgedPawn
    const pawnPtr = playerControllerValue.add(knownOffsets.AcknowledgedPawn);
    const pawnValue = Utils.readMemory(pawnPtr, 'pointer');
    if (!Utils.isValidAddress(pawnValue)) {
        Log.e("Invalid Pawn pointer");
        return null;
    }
    
    Log.i(`Local player found at ${pawnValue}`);
    return pawnValue;
}

// Validate player-related offsets
function validatePlayerOffsets(playerPtr) {
    Log.i("Validating player-related offsets");
    
    // Validate RootComponent
    const rootComponentPtr = playerPtr.add(knownOffsets.RootComponent);
    const rootComponentValue = Utils.readMemory(rootComponentPtr, 'pointer');
    const isRootComponentValid = Utils.isValidAddress(rootComponentValue) && Utils.isLikelyPointer(rootComponentValue);
    Log.offset("RootComponent", rootComponentPtr, rootComponentValue, isRootComponentValid);
    
    if (isRootComponentValid) {
        // Validate Position
        const positionPtr = rootComponentValue.add(knownOffsets.Position);
        const positionX = Utils.readMemory(positionPtr, 'float');
        const positionY = Utils.readMemory(positionPtr.add(4), 'float');
        const positionZ = Utils.readMemory(positionPtr.add(8), 'float');
        const isPositionValid = positionX !== null && positionY !== null && positionZ !== null;
        Log.offset("Position", positionPtr, `(${positionX}, ${positionY}, ${positionZ})`, isPositionValid);
    }
    
    // Validate PlayerState
    const playerStatePtr = playerPtr.add(knownOffsets.PlayerState);
    const playerStateValue = Utils.readMemory(playerStatePtr, 'pointer');
    const isPlayerStateValid = Utils.isValidAddress(playerStateValue) && Utils.isLikelyPointer(playerStateValue);
    Log.offset("PlayerState", playerStatePtr, playerStateValue, isPlayerStateValid);
    
    if (isPlayerStateValid) {
        // Validate TeamID
        const teamIDPtr = playerStateValue.add(knownOffsets.TeamID);
        const teamIDValue = Utils.readMemory(teamIDPtr, 'int');
        const isTeamIDValid = teamIDValue !== null;
        Log.offset("TeamID", teamIDPtr, teamIDValue, isTeamIDValid);
    }
    
    // Validate Health
    const healthPtr = playerPtr.add(knownOffsets.Health);
    const healthValue = Utils.readMemory(healthPtr, 'float');
    const isHealthValid = healthValue !== null && healthValue >= 0 && healthValue <= 100;
    Log.offset("Health", healthPtr, healthValue, isHealthValid);
    
    // Validate HealthMax
    const healthMaxPtr = playerPtr.add(knownOffsets.HealthMax);
    const healthMaxValue = Utils.readMemory(healthMaxPtr, 'float');
    const isHealthMaxValid = healthMaxValue !== null && healthMaxValue > 0;
    Log.offset("HealthMax", healthMaxPtr, healthMaxValue, isHealthMaxValid);
}

// Scan for strings
function scanForStrings(targetModule) {
    Log.highlight("Scanning for Strings");
    
    // Interesting string patterns to look for
    const patterns = [
        "UWorld",
        "GameInstance",
        "PlayerController",
        "Pawn",
        "Actor",
        "Component",
        "SDK",
        "Initialize",
        "Config",
        "Version"
    ];
    
    // Scan memory for strings
    Process.enumerateRanges('r--').forEach(range => {
        if (range.base >= targetModule.base && 
            range.base.add(range.size) <= targetModule.base.add(targetModule.size)) {
            
            try {
                const bytes = Memory.readByteArray(range.base, Math.min(range.size, 4096));
                const view = new Uint8Array(bytes);
                
                let currentString = "";
                
                for (let i = 0; i < view.length; i++) {
                    if (view[i] >= 32 && view[i] <= 126) { // Printable ASCII
                        currentString += String.fromCharCode(view[i]);
                    } else if (currentString.length >= 4) { // End of string
                        // Check if string matches any pattern
                        for (const pattern of patterns) {
                            if (currentString.includes(pattern)) {
                                const stringAddress = range.base.add(i - currentString.length);
                                const offset = Utils.addressToOffset(stringAddress, config.targetModule);
                                Log.i(`Found string "${currentString}" at ${stringAddress} (offset: 0x${offset.toString(16).toUpperCase()})`);
                                break;
                            }
                        }
                        
                        currentString = "";
                    } else {
                        currentString = "";
                    }
                }
                
                // Check the last string
                if (currentString.length >= 4) {
                    for (const pattern of patterns) {
                        if (currentString.includes(pattern)) {
                            const stringAddress = range.base.add(view.length - currentString.length);
                            const offset = Utils.addressToOffset(stringAddress, config.targetModule);
                            Log.i(`Found string "${currentString}" at ${stringAddress} (offset: 0x${offset.toString(16).toUpperCase()})`);
                            break;
                        }
                    }
                }
            } catch (e) {
                Log.d(`Failed to scan memory region: ${e}`);
            }
        }
    });
    
    Log.highlight("String Scanning Complete");
}

// Scan for pointers
function scanForPointers(targetModule) {
    Log.highlight("Scanning for Pointers");
    
    // Scan for pointers to UWorld
    const uWorldPtr = Utils.offsetToAddress(knownOffsets.UWorld, config.targetModule);
    if (uWorldPtr) {
        const uWorldValue = Utils.readMemory(uWorldPtr, 'pointer');
        if (Utils.isValidAddress(uWorldValue)) {
            Log.i(`Scanning for pointers to UWorld (${uWorldValue})`);
            
            // Scan memory for pointers to UWorld
            Process.enumerateRanges('r--').forEach(range => {
                if (range.base >= targetModule.base && 
                    range.base.add(range.size) <= targetModule.base.add(targetModule.size)) {
                    
                    try {
                        const pointerSize = Process.pointerSize;
                        const count = Math.floor(range.size / pointerSize);
                        
                        for (let i = 0; i < count; i++) {
                            const address = range.base.add(i * pointerSize);
                            const value = Utils.readMemory(address, 'pointer');
                            
                            if (value && value.equals(uWorldValue)) {
                                const offset = Utils.addressToOffset(address, config.targetModule);
                                Log.i(`Found pointer to UWorld at ${address} (offset: 0x${offset.toString(16).toUpperCase()})`);
                            }
                        }
                    } catch (e) {
                        Log.d(`Failed to scan memory region: ${e}`);
                    }
                }
            });
        }
    }
    
    Log.highlight("Pointer Scanning Complete");
}

// Start the script
initialize();
