#include "comparison.h"
#define RESULT u32

NOINLINE u32 helper(u32 x)
{
    x = x * 1664525u + 1013904223u;
    return x ^ (x >> 13);
}

NOINLINE u32 kernel(u32 n)
{
    u32 i, x = 1u;
    for (i = 0; i < n; ++i)
        x = helper(x);
    return x & 0x7fffffffu;
}

WRAPPERS
