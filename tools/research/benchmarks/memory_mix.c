#define PREPARE() prepare()
#include "comparison.h"
#define RESULT u32

static u32 values[256];

static void prepare(void)
{
    u32 i;
    for (i = 0; i < 256u; ++i)
        values[i] = i * 17u + 3u;
}

NOINLINE u32 kernel(u32 n)
{
    u32 i, sum = 0;
    for (i = 0; i < n; ++i) {
        u32 index = i & 255u;
        u32 x = values[index];
        x = x * 1664525u + 1013904223u;
        values[index] = x;
        sum ^= x;
    }
    return sum & 0x7fffffffu;
}

WRAPPERS
