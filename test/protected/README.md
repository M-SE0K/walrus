# G1 integration tests

Requires Python 3, `wat2wasm`, `wasm-validate`, and a 64-bit Walrus shell.

```bash
python3 test/protected/run_g1_tests.py --engine /path/to/walrus
```

Generated modules and protected files live in temporary directories. The test runner checks independent expected values, original/protected behavior, original-body removal, deterministic encoding, packed locals, calls, and invalid payload rejection.

See [G1 implementation and server instructions](../../docs/research/g1-implementation.md) for the format, supported subset, build options, and G0/G1 measurements.
