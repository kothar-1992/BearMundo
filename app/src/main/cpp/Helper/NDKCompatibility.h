#ifndef NDK_COMPATIBILITY_H
#define NDK_COMPATIBILITY_H

// This header must be included before any standard C++ headers
// to ensure compatibility with the Android NDK

// Disable __float128 for Android NDK compatibility
// These defines prevent the NDK from using __float128 which causes build errors
#define __MATH_DECLARE_LDOUBLE 1
#define __MATH_DECLARING_DOUBLE 1
#define __MATH_DECLARING_FLOATN 1
#define __MATH_PRECALC_REAL_FLOAT128 1

// Prevent __float128 type from being defined
#ifdef __ANDROID__
    // For Android NDK, explicitly disable __float128 support
    #undef __SIZEOF_FLOAT128__
    #define __SIZEOF_FLOAT128__ 0

    // Disable long double extensions that might cause issues
    #ifndef __NO_LONG_DOUBLE_MATH
        #define __NO_LONG_DOUBLE_MATH 1
    #endif
#endif

// Ensure size_t is properly defined
#ifndef size_t
typedef __SIZE_TYPE__ size_t;
#endif

// Note: Removed invalid operator overloads that violated C++ standards.
// The __float128 compatibility is now handled through preprocessor defines above.
// This approach is safer and doesn't violate C++ operator overloading rules.

#endif // NDK_COMPATIBILITY_H
