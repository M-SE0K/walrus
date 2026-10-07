# Wasm protection research tools

`protect.py` creates G1/G2/G3 modules and manifests. `measure.py` checks results and times one new Walrus process per observation. `decode_protected.py` recovers the stored opcode mapping and expands fused instructions. `profile_protected.py` collects instrumented dispatch counts separately from timing.

The local C benchmark comparison adds:

- `build_comparison.py`: one preprocessed source and matching Emscripten flags for G0 and Tigress G4; derive v5 G1/G2/G3 from G0. Links a shared constructor to run `main` through the reactor initializer before exports, including Tigress VM initialization. Checks outputs and remaining loops, and records commands and hashes. Tigress is required unless `--without-g4` is explicit. `--tigress-home` overrides the environment or detected distribution directory.
- `measure_comparison.py`: validate the generated suite and measure its groups in shuffled rounds. Saves raw samples, actual execution order, time statistics, sizes and G0 ratios.
- `comparison_support.py`: shared Wasm export/initializer and artifact-manifest checks.
- `benchmarks/`: six scalar C pilots for integers, floats, memory and calls.

G4 measurement requires its artifact manifest; merely labeling a file G4 does not bypass provenance checks. The timer includes process startup, module parsing, instantiation/initialization, export execution, output capture and shutdown. It does not measure only the calculation function.

See [local commands and recorded results](../../docs/research/tigress-comparison.md). G0--G4 were executed locally with Emscripten 3.1.69 and Tigress 4.0.11. These tools do not measure resistance to logic recovery.
