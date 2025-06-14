#include <jni.h>
#include "KeyAuthNative.h"

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_KeyAuthBridge_initialize(JNIEnv* env, jobject thiz, jobject context) {
    return KeyAuthNative::getInstance()->initialize(env, context);
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_KeyAuthBridge_authenticate(JNIEnv* env, jobject thiz, jstring licenseKey, jobject context) {
    const char* key = env->GetStringUTFChars(licenseKey, nullptr);
    bool result = KeyAuthNative::getInstance()->authenticate(key, env, context);
    env->ReleaseStringUTFChars(licenseKey, key);
    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_KeyAuthBridge_validateSession(JNIEnv* env, jobject thiz) {
    return KeyAuthNative::getInstance()->validateSession();
}

JNIEXPORT void JNICALL
Java_com_bearmod_security_KeyAuthBridge_logout(JNIEnv* env, jobject thiz) {
    KeyAuthNative::getInstance()->logout();
}

JNIEXPORT jboolean JNICALL
Java_com_bearmod_security_KeyAuthBridge_isDeviceSecure(JNIEnv* env, jobject thiz) {
    return KeyAuthNative::getInstance()->isDeviceSecure();
}

} // extern "C" 