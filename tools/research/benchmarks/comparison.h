/* Shared, import-free wrappers for the local G0--G4 pilot. */
typedef unsigned int u32;
typedef unsigned long long u64;
#define NOINLINE __attribute__((noinline))

#ifndef PREPARE
#define PREPARE() ((void)0)
#endif

#define BENCH(name, count) \
    RESULT name(void) { PREPARE(); return kernel(count); }
#define WRAPPERS \
    BENCH(bench_zero, 0u) \
    BENCH(bench_one, 1u) \
    BENCH(bench_1000, 1000u) \
    BENCH(bench_100k, 100000u) \
    BENCH(bench_1m, 1000000u) \
    BENCH(bench_10m, 10000000u) \
    int main(int argc, char **argv, char **envp) { \
        (void)argc; (void)argv; (void)envp; return 0; }
