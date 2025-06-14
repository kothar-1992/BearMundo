# ===========================
# BearMod - ProGuard Rules (Merged)
# ===========================

# --- Keep JNI/native method bindings ---
-keepclasseswithmembernames class * {
    native <methods>;
}

# --- Keep core native interfaces and bridges ---
-keep class com.bearmod.NativeUtils { *; }
-keep class com.bearmod.ESPView { *; }
-keep class com.bearmod.core.NativeBridge { *; }
-keep class com.bearmod.core.hooks.** { *; }
-keep class com.bearmod.core.hooks.HookManager { *; }

# --- Keep public API and loader classes for target apps ---
-keep class com.bearmod.targetapp.MainActivity { *; }
-keep class com.bearmod.targetapp.SignatureVerifier { *; }
-keep class com.bearmod.core.BearModCore {
    public static ** getInstance(android.content.Context);
    public boolean initialize();
    public ** getHookManager();
    public android.content.Context getContext();
    public boolean isInitialized();
}

# --- Public API safety ---
-keep public class com.bearmod.core.** { *; }
-keep public class com.bearmod.targetapp.** { *; }

# --- Optional: Allow loading from native code ---
-keep class com.bearmod.security.** { *; }
-keep class com.bearmod.keyauth.** { *; }

# --- Remove logging in release ---
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}
