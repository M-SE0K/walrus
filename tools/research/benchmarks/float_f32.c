#include "comparison.h"
#define RESULT float

NOINLINE float kernel(u32 n)
{
    u32 i;
    float sum = 0.0f;
    for (i = 0; i < n; ++i)
        sum += 0.5f;
    return sum;
}

WRAPPERS
