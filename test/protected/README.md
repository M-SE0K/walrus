# G1/G2/G3 integration tests

Requires Python 3, `wat2wasm`, `wasm-validate`, and a 64-bit Walrus shell.

```bash
python3 test/protected/run_g1_tests.py --engine /path/to/walrus
python3 test/protected/run_g2_tests.py --engine /path/to/walrus
python3 test/protected/run_g3_tests.py --engine /path/to/walrus
python3 test/protected/run_extended_tests.py --engine /path/to/walrus
python3 test/protected/run_float_tests.py --engine /path/to/walrus
python3 test/protected/run_comparison_tests.py --engine /path/to/walrus --emcc /path/to/emcc --tigress /path/to/tigress
```

Generated modules and protected files live in temporary directories. The test runner checks independent expected values, original/protected behavior, original-body removal, deterministic encoding, packed locals, calls, and invalid payload rejection.

See [G1 implementation and server instructions](../../docs/research/g1-implementation.md) for the format, supported subset, build options, and G0/G1 measurements.

G2 adds per-function opcode permutations, deterministic uint64 seeds, common-format G1/G2 comparisons, rejection of invalid mappings, all 46 supported operations, and stored-table recovery verified against G1 canonical instruction streams.

See [G2 implementation](../../docs/research/g2-implementation.md) and [G2 server instructions](../../docs/g2-server-testing.md) for manifests, recovery, and G0/G1/G2 measurements.

G3 adds two-instruction fusion, branch-entry and relocation checks, frame-alias and intermediate-value oracles, v1/v2 compatibility, exact base-stream expansion, and separate dispatch profiling. Its compiler-pass test also requires `c++` (provided by Ubuntu's `build-essential`).

See [G3 implementation](../../docs/research/g3-implementation.md) and [G3 server instructions](../../docs/g3-server-testing.md). Re-run CMake configuration before building an existing build directory so it discovers `ProtectedFusion.cpp`.

Protected format v4 (`--extended`) adds integer operations, integer select/br_table, memory32 loads/stores/size/grow, i32/i64 globals, direct and indirect calls, recursion and multiple integer returns. The extended suite has 21 tests and checks independent integer oracles, memory/global effects, native imports, multi-memory, call traps, malformed auxiliary tables, and v4 recovery. `extended-pilot.wat` contains an integer mixer, an array calculation, recursive GCD, and a protected caller that combines their results.

See [extended implementation](../../docs/research/extended-implementation.md) and [extended server instructions](../../docs/extended-server-testing.md).

Protected format v5 (`--floating-point`) includes v4 and adds scalar f32/f64 calculations, conversions, state access and mixed calls/returns. The 15 float tests include six upstream scalar spec suites with protected G2/G3 function bodies. They also require `wast2json` from wabt. `float-pilot.wat` supports reproducible f32/f64 latency measurements using `measure.py --expected` and separate dispatch profiling.

See [floating-point implementation](../../docs/research/floating-point-implementation.md) and [floating-point server instructions](../../docs/floating-point-server-testing.md).

The 16 comparison tests cover reactor initialization, the shared constructor calling main once, artifact/hash/group checks, required G4 provenance, shuffled process measurements, preservation of existing outputs, a real C -> Wasm -> G0/G1/G2/G3 build, and a real Tigress G4 build and measurement. Emscripten is required for the C tests and Tigress for the G4 integration test; missing optional tools cause skips. They also need `wasm-objdump` for loop inspection. Metadata fixtures are not Tigress performance results. See [local Tigress comparison setup](../../docs/research/tigress-comparison.md).
