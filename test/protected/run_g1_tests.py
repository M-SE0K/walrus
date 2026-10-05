#!/usr/bin/env python3
"""G1 integration tests; requires wat2wasm, wasm-validate and a Walrus shell."""
import argparse
import itertools
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

NAME = b"walrus.protected.g1"
HEADER = b"\x00asm\x01\x00\x00\x00"
PILOT = Path(__file__).with_name("pilot.wat").read_text()
EXPECTED = ["23", "3", "500500", "500000500000", "50000005000000"]
ENGINE = None


def uleb(value):
    out = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        out.append(byte | (128 if value else 0))
        if not value:
            return bytes(out)


def read_uleb(data, offset):
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
        shift += 7


def sections(data):
    assert data[:8] == HEADER
    result = []
    offset = 8
    while offset < len(data):
        kind = data[offset]
        size, begin = read_uleb(data, offset + 1)
        result.append((kind, data[begin:begin + size]))
        offset = begin + size
    return result


def module_bytes(items):
    return HEADER + b"".join(bytes([kind]) + uleb(len(data)) + data for kind, data in items)


def bodies(items):
    code = next(data for kind, data in items if kind == 10)
    count, offset = read_uleb(code, 0)
    out = []
    for _ in range(count):
        size, offset = read_uleb(code, offset)
        out.append(code[offset:offset + size])
        offset += size
    assert offset == len(code)
    return out


def payload_location(items):
    for index, (kind, data) in enumerate(items):
        if kind == 0:
            size, begin = read_uleb(data, 0)
            if data[begin:begin + size] == NAME:
                return index, bytearray(data[begin + size:])
    raise AssertionError("missing G1 section")


def replace_payload(items, payload):
    index, _ = payload_location(items)
    out = list(items)
    out[index] = (0, uleb(len(NAME)) + NAME + bytes(payload))
    return out


def record_layout(payload, offset=24):
    index, frame, params, results, count, mapping = struct.unpack_from("<6I", payload, offset)
    mapping_start = offset + 24 + params + results
    stream_start = mapping_start + 2 * mapping
    return index, frame, count, mapping_start, stream_start


def skeleton_hash(items):
    value = 14695981039346656037
    for byte in module_bytes([(kind, data) for kind, data in items if kind]):
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


class G1Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="walrus-g1-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ids = itertools.count()

    def command(self, *args):
        return subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=30)

    def compile(self, source=PILOT, names=False, features=()):
        stem = self.root / f"module-{next(self.ids)}"
        wat = stem.with_suffix(".wat")
        wasm = stem.with_suffix(".wasm")
        wat.write_text(source)
        flags = ["--debug-names"] if names else []
        result = self.command("wat2wasm", *flags, *features, wat, "-o", wasm)
        self.assertEqual(result.returncode, 0, result.stderr)
        return wasm

    def protect(self, original, targets=(0, 3)):
        output = self.root / f"protected-{next(self.ids)}.wasm"
        args = [ENGINE]
        for target in targets:
            args.extend(["--protect-function", target])
        result = self.command(*args, "--output", output, original)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command("wasm-validate", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def values(self, wasm, export="*"):
        result = self.command(ENGINE, "--run-export", export, wasm)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def rejected(self, data, message):
        file = self.root / f"bad-{next(self.ids)}.wasm"
        file.write_bytes(data)
        result = self.command("wasm-validate", file)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command(ENGINE, "--run-export", "sum_1000", file)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_pilot_and_unchanged_wrappers(self):
        original = self.compile(names=True)
        protected = self.protect(original)
        self.assertEqual(self.values(original), EXPECTED)
        self.assertEqual(self.values(protected), EXPECTED)
        before = sections(original.read_bytes())
        after = sections(protected.read_bytes())
        old_bodies, new_bodies = bodies(before), bodies(after)
        for index, (old, new) in enumerate(zip(old_bodies, new_bodies)):
            self.assertEqual(new, b"\x00\x00\x0b" if index in (0, 3) else old)
        self.assertEqual([data for kind, data in before if kind and kind != 10],
                         [data for kind, data in after if kind and kind != 10])
        self.assertEqual(sum(kind == 0 for kind, _ in after), 1)
        again = self.protect(original, (3, 0))
        self.assertEqual(protected.read_bytes(), again.read_bytes())
        # With the payload removed, execution reaches the stub and traps.
        stripped = self.root / "stripped.wasm"
        stripped.write_bytes(module_bytes([(kind, data) for kind, data in after if kind]))
        result = self.command(ENGINE, "--run-export", "sum_1000", stripped)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unreachable", result.stderr)

    def test_multiple_inputs_and_function_names(self):
        rng = random.Random(260106)
        xs = [-(1 << 31), -1, 0, 10, 11, (1 << 31) - 1] + [rng.randint(-10000, 10000) for _ in range(12)]
        ns = [0, 1, 2, 65536] + [rng.randrange(5000) for _ in range(12)]
        source = PILOT.rstrip()[:-1]
        expected = list(EXPECTED)
        for index, x in enumerate(xs):
            source += f'\n(func (export "x{index}") (result i32) i32.const {x} call $calc)'
            result = (x + 3 if x > 10 else x - 2) & 0xffffffff
            expected.append(str(result if result < 0x80000000 else result - (1 << 32)))
        for index, n in enumerate(ns):
            source += f'\n(func (export "n{index}") (result i64) i32.const {n} call $sum_to_n)'
            expected.append(str(n * (n + 1) // 2))
        source = (source + "\n)").replace("$calc", "$opaque_a").replace("$sum_to_n", "$opaque_b")
        original = self.compile(source)
        protected = self.protect(original)
        self.assertEqual(self.values(original), expected)
        self.assertEqual(self.values(protected), expected)

    def test_changed_body_changes_bytecode_and_result(self):
        positive = self.protect(self.compile(), (3,))
        # Wasm pushes i before sum: replacing add with sub computes i - sum.
        changed_original = self.compile(PILOT.replace("i64.add", "i64.sub"))
        changed = self.protect(changed_original, (3,))
        self.assertNotEqual(positive.read_bytes(), changed.read_bytes())
        self.assertEqual(self.values(positive, "sum_1000"), ["500500"])
        self.assertEqual(self.values(changed_original, "sum_1000"), ["500"])
        self.assertEqual(self.values(changed, "sum_1000"), ["500"])

    def test_packed_locals_multiple_parameters_and_integer_operations(self):
        source = '''(module
          (func $packed (param i32) (result i32)
            (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
            local.get 0 local.set 14 local.get 14)
          (func $mixed (param i32 i64) (result i64)
            local.get 0 i64.extend_i32_s local.get 1 i64.mul i64.const 3 i64.add)
          (func $bits (param i32) (result i32)
            local.get 0 i32.const 7 i32.mul i32.const -1515870811 i32.xor)
          (func (export "packed") (result i32) i32.const -123 call $packed)
          (func (export "mixed") (result i64) i32.const -9 i64.const 7 call $mixed)
          (func (export "bits") (result i32) i32.const 2147483647 call $bits))'''
        original = self.compile(source)
        protected = self.protect(original, (0, 1, 2))
        bits = ((2147483647 * 7) ^ 0xa5a5a5a5) & 0xffffffff
        expected = ["-123", "-60", str(bits if bits < 0x80000000 else bits - (1 << 32))]
        self.assertEqual(self.values(original), expected)
        self.assertEqual(self.values(protected), expected)

    def test_void_return_and_unreachable_trap(self):
        original = self.compile('(module (func $f (local i32) i32.const 5 local.set 0) (func (export "run") call $f))')
        self.assertEqual(self.values(self.protect(original, (0,)), "run"), [])
        original = self.compile('(module (func $f unreachable) (func (export "run") call $f))')
        protected = self.protect(original, (0,))
        for file in (original, protected):
            result = self.command(ENGINE, "--run-export", "run", file)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unreachable", result.stderr)

    def test_indirect_call_from_an_unprotected_function(self):
        source = '''(module
          (type $t (func (param i32) (result i32)))
          (func $f (type $t) local.get 0 i32.const 3 i32.add)
          (table 1 funcref) (elem (i32.const 0) $f)
          (func (export "run") (result i32)
            i32.const 20 i32.const 0 call_indirect (type $t)))'''
        original = self.compile(source)
        protected = self.protect(original, (0,))
        self.assertEqual(self.values(original, "run"), ["23"])
        self.assertEqual(self.values(protected, "run"), ["23"])

    def test_imports_are_included_in_function_indices(self):
        original = self.compile('(module (import "env" "unused" (func)) (func (export "f") (result i32) i32.const 9))')
        protected = self.protect(original, (1,))
        self.assertEqual(bodies(sections(protected.read_bytes())), [b"\x00\x00\x0b"])
        _, payload = payload_location(sections(protected.read_bytes()))
        self.assertEqual(struct.unpack_from("<I", payload, 24)[0], 1)
        output = self.root / "bad-target.wasm"
        result = self.command(ENGINE, "--protect-function", 0, "--output", output, original)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a defined function", result.stderr)
        self.assertFalse(output.exists())

    def test_tail_call_from_an_unprotected_function(self):
        source = '''(module
          (func $f (param i32) (result i32) local.get 0 i32.const 3 i32.add)
          (func (export "run") (result i32) i32.const 20 return_call $f))'''
        original = self.compile(source, features=("--enable-tail-call",))
        protected = self.root / "tail.wasm"
        result = self.command(ENGINE, "--enable-web-assembly3", "--protect-function", 0, "--output", protected, original)
        self.assertEqual(result.returncode, 0, result.stderr)
        for file in (original, protected):
            result = self.command(ENGINE, "--enable-web-assembly3", "--run-export", "run", file)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "23")

    def test_data_global_initializers_and_synthetic_target_rejection(self):
        source = '''(module (memory 1)
          (global i32 (i32.const 9)) (data (i32.const 0) "abc")
          (table 1 funcref)
          (func $f (result i32) i32.const 7 i32.const 3 i32.add)
          (elem (i32.const 0) $f)
          (func (export "run") (result i32) call $f))'''
        original = self.compile(source)
        protected = self.protect(original, (0,))
        self.assertEqual(self.values(original, "run"), ["10"])
        self.assertEqual(self.values(protected, "run"), ["10"])
        result = self.command(ENGINE, "--protect-function", 2, "--output", self.root / "synthetic.wasm", original)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a defined function", result.stderr)

    def test_unsupported_functions_fail_without_output(self):
        sources = [
            '(module (memory 1) (func (param i32) (result i32) local.get 0 i32.load))',
            '(module (func (param f32) (result f32) local.get 0))',
            '(module (func (result i32 i64) i32.const 1 i64.const 2))',
            '(module (func $f) (start $f))',
            '(module (func $f) (func call $f))',
        ]
        for source in sources:
            with self.subTest(source=source):
                original = self.compile(source)
                output = self.root / f"unsupported-{next(self.ids)}.wasm"
                target = 1 if '(func call $f)' in source else 0
                result = self.command(ENGINE, "--protect-function", target, "--output", output, original)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("G1:", result.stderr)
                self.assertFalse(output.exists())

    def test_malformed_payloads_are_rejected(self):
        protected = self.protect(self.compile())
        items = sections(protected.read_bytes())
        _, payload = payload_location(items)
        _, _, count, mapping, stream = record_layout(payload)
        cases = []
        def mutation(offset, fmt, value, message):
            changed = bytearray(payload)
            struct.pack_into(fmt, changed, offset, value)
            cases.append((changed, message))
        mutation(0, "<I", 0, "magic")
        mutation(4, "<I", 99, "version")
        mutation(8, "<I", 4, "ABI")
        mutation(12, "<Q", 0, "checksum")
        mutation(20, "<I", 0xffffffff, "function count")
        mutation(24, "<I", 0xffffffff, "function index")
        mutation(28, "<I", 65536, "frame size")
        mutation(32, "<I", 99, "signature")
        mutation(40, "<I", 0xffffffff, "instruction count")
        mutation(44, "<I", 0, "mapping size")
        mutation(48, "<B", 0x7e, "parameter type")
        mutation(mapping, "<H", 1, "identity")
        mutation(stream, "<H", 65535, "opcode")
        mutation(stream + 2, "<H", 1, "reserved")
        mutation(stream + 12, "<I", 0xffffffff, "frame access")
        for index in range(count):
            start = stream + index * 24
            if struct.unpack_from("<H", payload, start)[0] in (4, 5, 6):
                mutation(start + 16, "<Q", count, "branch target")
                break
        else:
            self.fail("fixture should include a branch")
        mutation(stream + (count - 1) * 24, "<H", 0, "falls through")
        next_record = stream + count * 24
        mutation(next_record, "<I", 0, "duplicate protected function")
        cases.extend([(payload[:-1], "instruction count"), (payload + b"x", "trailing")])
        for changed, message in cases:
            with self.subTest(message=message):
                self.rejected(module_bytes(replace_payload(items, changed)), message)
        section_index, _ = payload_location(items)
        self.rejected(module_bytes(items + [items[section_index]]), "duplicate protection section")

    def test_loader_requires_stub_even_with_matching_checksum(self):
        original = self.compile()
        protected = self.protect(original)
        items = sections(protected.read_bytes())
        changed_bodies = bodies(items)
        changed_bodies[0] = bodies(sections(original.read_bytes()))[0]
        code = uleb(len(changed_bodies)) + b"".join(uleb(len(body)) + body for body in changed_bodies)
        changed = [(kind, code if kind == 10 else data) for kind, data in items]
        _, payload = payload_location(changed)
        struct.pack_into("<Q", payload, 12, skeleton_hash(changed))
        self.rejected(module_bytes(replace_payload(changed, payload)), "canonical stub")

    def test_cli_validation_and_existing_output(self):
        original = self.compile()
        output = self.root / "existing.wasm"
        output.write_bytes(b"keep me")
        result = self.command(ENGINE, "--protect-function", 3, "--output", output, original)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"keep me")
        for target in ("-1", "abc", "4294967296", "999"):
            result = self.command(ENGINE, "--protect-function", target, "--output", self.root / "bad.wasm", original)
            self.assertNotEqual(result.returncode, 0)
        result = self.command(ENGINE, "--protect-function", 3, "--protect-function", 3, "--output", self.root / "bad.wasm", original)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate protection target", result.stderr)
        result = self.command(ENGINE, "--run-export", "missing", original)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not found", result.stderr)
        protected = self.protect(original)
        result = self.command(ENGINE, "--protect-function", 3, "--output", self.root / "again.wasm", protected)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already protected", result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    ENGINE = args.engine.resolve(strict=True)
    unittest.main(argv=[__file__, *remaining], verbosity=2)
