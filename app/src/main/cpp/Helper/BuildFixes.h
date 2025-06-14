#ifndef BUILD_FIXES_H
#define BUILD_FIXES_H

// Disable __float128 for Android NDK compatibility
#define __MATH_DECLARE_LDOUBLE 1
#define __MATH_DECLARING_DOUBLE 1
#define __MATH_DECLARING_FLOATN 1

// Include standard headers
#include <stddef.h>
#include <cstddef>
#include <math.h>
#include <cmath>

// Define size_t if not already defined
#ifndef size_t
typedef __SIZE_TYPE__ size_t;
#endif

// Define mathematical functions if not already defined
#ifndef signbit
#define signbit(x) __builtin_signbit(x)
#endif

#ifndef fpclassify
#define fpclassify(x) __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, x)
#endif

#ifndef isfinite
#define isfinite(x) __builtin_isfinite(x)
#endif

#ifndef isinf
#define isinf(x) __builtin_isinf(x)
#endif

#ifndef isnan
#define isnan(x) __builtin_isnan(x)
#endif

#ifndef isnormal
#define isnormal(x) __builtin_isnormal(x)
#endif

#ifndef isgreater
#define isgreater(x, y) __builtin_isgreater(x, y)
#endif

#ifndef isgreaterequal
#define isgreaterequal(x, y) __builtin_isgreaterequal(x, y)
#endif

#ifndef isless
#define isless(x, y) __builtin_isless(x, y)
#endif

#ifndef islessequal
#define islessequal(x, y) __builtin_islessequal(x, y)
#endif

#ifndef islessgreater
#define islessgreater(x, y) __builtin_islessgreater(x, y)
#endif

#ifndef isunordered
#define isunordered(x, y) __builtin_isunordered(x, y)
#endif

#endif // BUILD_FIXES_H
