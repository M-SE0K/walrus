#include "comparison.h"
#define RESULT double

NOINLINE double kernel(u32 n)
{
    u32 i;
    double sum = 0.0;
    for (i = 0; i < n; ++i)
        sum += 0.5;
    return sum;
}

WRAPPERS
