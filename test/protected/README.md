# G1/G2/G3 integration tests

Requires Python 3, `wat2wasm`, `wasm-validate`, and a 64-bit Walrus shell.

```bash
python3 test/protected/run_g1_tests.py --engine /path/to/walrus
python3 test/protected/run_g2_tests.py --engine /path/to/walrus
python3 test/protected/run_g3_tests.py --engine /path/to/walrus
```

Generated modules and protected files live in temporary directories. The test runner checks independent expected values, original/protected behavior, original-body removal, deterministic encoding, packed locals, calls, and invalid payload rejection.

See [G1 implementation and server instructions](../../docs/research/g1-implementation.md) for the format, supported subset, build options, and G0/G1 measurements.

G2 adds per-function opcode permutations, deterministic uint64 seeds, common-format G1/G2 comparisons, rejection of invalid mappings, all 46 supported operations, and stored-table recovery verified against G1 canonical instruction streams.

See [G2 implementation](../../docs/research/g2-implementation.md) and [G2 server instructions](../../docs/g2-server-testing.md) for manifests, recovery, and G0/G1/G2 measurements.

G3 adds two-instruction fusion, branch-entry and relocation checks, frame-alias and intermediate-value oracles, v1/v2 compatibility, exact base-stream expansion, and separate dispatch profiling. Its compiler-pass test also requires `c++` (provided by Ubuntu's `build-essential`).

See [G3 implementation](../../docs/research/g3-implementation.md) and [G3 server instructions](../../docs/g3-server-testing.md). Re-run CMake configuration before building an existing build directory so it discovers `ProtectedFusion.cpp`.
