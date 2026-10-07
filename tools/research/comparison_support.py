"""Artifact checks shared by the comparison builder and the process timer."""
import hashlib
import json
from pathlib import Path

from protected_format import HEADER, Reader, read_protection

SCHEMA = "walrus.comparison.v1"
BENCHMARKS = ("integer_mix", "sum_i64", "float_f32", "float_f64", "memory_mix", "call_mix")
INPUTS = {"bench_zero": 0, "bench_one": 1, "bench_1000": 1000,
          "bench_100k": 100000, "bench_1m": 1000000, "bench_10m": 10000000}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sections(data):
    if data[:8] != HEADER:
        raise ValueError("expected a core Wasm module")
    reader = Reader(data[8:])
    result = []
    while reader.remaining():
        kind = reader.number(1)
        result.append((kind, reader.take(reader.uleb())))
    return result


def function_exports(data):
    exports = {}
    for kind, body in sections(data):
        if kind != 7:
            continue
        reader = Reader(body)
        for _ in range(reader.uleb()):
            name = reader.take(reader.uleb()).decode("utf-8")
            export_kind, index = reader.number(1), reader.uleb()
            if export_kind == 0:
                if name in exports:
                    raise ValueError("duplicate function export")
                exports[name] = index
        if reader.remaining():
            raise ValueError("trailing export data")
    return exports


def function_body(data, index):
    # Comparison modules have no imports, so function and code indices coincide.
    for kind, body in sections(data):
        if kind == 10:
            reader = Reader(body)
            count = reader.uleb()
            if index >= count:
                raise ValueError("function index is outside the code section")
            for i in range(count):
                function = reader.take(reader.uleb())
                if i == index:
                    return function
    raise ValueError("missing code section")


def uleb(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def initialize_reactor(data):
    """Have normal instantiation call Emscripten's reactor initializer once.

    This happens BEFORE protection, so its skeleton checksum remains valid.
    No runtime changes or per-export timing exceptions are needed.
    """
    parsed = sections(data)
    exports = function_exports(data)
    for kind, body in parsed:
        if kind == 2 and Reader(body).uleb():
            raise ValueError("comparison modules must have no imports; inspect the compiler/Tigress output")
        if kind == 8:
            raise ValueError("unexpected pre-existing Wasm start section")
    if "_initialize" not in exports:
        raise ValueError("missing _initialize; compile as a standalone Emscripten reactor")
    index = exports["_initialize"]
    # Confirm the initializer is () -> (), rather than patching an arbitrary export.
    types, function_types = [], []
    for kind, body in parsed:
        reader = Reader(body)
        if kind == 1:
            for _ in range(reader.uleb()):
                if reader.number(1) != 0x60:
                    raise ValueError("comparison pilot requires ordinary function types")
                params = reader.take(reader.uleb())
                results = reader.take(reader.uleb())
                types.append((params, results))
        elif kind == 3:
            function_types = [reader.uleb() for _ in range(reader.uleb())]
    if index >= len(function_types) or function_types[index] >= len(types) or types[function_types[index]] != (b"", b""):
        raise ValueError("_initialize must have type () -> ()")
    result, inserted = bytearray(HEADER), False
    for kind, body in parsed:
        if not inserted and kind and kind > 8:
            start = uleb(index)
            result += b"\x08" + uleb(len(start)) + start
            inserted = True
        result += bytes((kind,)) + uleb(len(body)) + body
    if not inserted:
        start = uleb(index)
        result += b"\x08" + uleb(len(start)) + start
    return bytes(result), index


def expected_outputs(benchmark):
    """Independent integer reference; half-integer float sums are exact here."""
    if benchmark not in BENCHMARKS:
        raise ValueError("unknown benchmark")
    if benchmark.startswith("float_"):
        return {name: f"{count * 0.5:.8f}" for name, count in INPUTS.items()}
    wanted = {count: name for name, count in INPUTS.items()}
    state, total = 1, 0
    values = [i * 17 + 3 for i in range(256)]
    result = {wanted[0]: str(1 if benchmark in ("integer_mix", "call_mix") else 0)}
    for count in range(1, max(wanted) + 1):
        if benchmark in ("integer_mix", "call_mix"):
            state = (state * 1664525 + 1013904223) & 0xffffffff
            state ^= state >> 13
            value = state & 0x7fffffff
        elif benchmark == "sum_i64":
            total += count ^ (count >> 3)
            value = total
        else:
            index = (count - 1) & 255
            state = (values[index] * 1664525 + 1013904223) & 0xffffffff
            values[index] = state
            total ^= state
            value = total & 0x7fffffff
        if count in wanted:
            result[wanted[count]] = str(value)
    return result


def load_artifact_manifest(path, wasm, group):
    """Bind labels to generated files; this is provenance, not authentication."""
    manifest = json.loads(Path(path).read_text())
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA or manifest.get("group") != group:
        raise ValueError("artifact manifest schema/group mismatch")
    artifact = manifest.get("artifact", {})
    wasm = Path(wasm)
    if not isinstance(artifact, dict) or artifact.get("sha256") != sha256(wasm) or artifact.get("bytes") != wasm.stat().st_size:
        raise ValueError("artifact manifest does not match Wasm bytes")
    expected = manifest.get("expected")
    if not isinstance(expected, dict) or not expected or any(
        not isinstance(name, str) or not name or not isinstance(value, str) or
        not value or value != value.strip() or "\n" in value for name, value in expected.items()
    ):
        raise ValueError("invalid expected outputs in artifact manifest")
    protection = read_protection(wasm.read_bytes())
    if group == "G4":
        tigress = manifest.get("tigress")
        if protection is not None or not isinstance(tigress, dict) or not tigress.get("version") or not tigress.get("command"):
            raise ValueError("G4 requires Tigress provenance and no Walrus protection section")
    elif (protection["group"] if protection else "G0") != group:
        raise ValueError("artifact manifest disagrees with Walrus protection group")
    return manifest
