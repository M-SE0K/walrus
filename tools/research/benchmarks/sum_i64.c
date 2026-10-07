#include "comparison.h"
#define RESULT u64

/* The XOR prevents the compiler replacing the loop with n*(n+1)/2. */
NOINLINE u64 kernel(u32 n)
{
    u32 i;
    u64 sum = 0;
    for (i = 1; i <= n; ++i)
        sum += (u64)(i ^ (i >> 3));
    return sum;
}

WRAPPERS
