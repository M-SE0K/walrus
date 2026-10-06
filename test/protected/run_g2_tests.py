#!/usr/bin/env python3
"""G2 integration: semantic agreement, reproducibility, bad mappings and recovery."""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import run_g1_tests as g1

RESEARCH = Path(__file__).resolve().parents[2] / "tools" / "research"
sys.path.insert(0, str(RESEARCH))
from decode_protected import recover
from protected_format import COMMON_NAME, OPCODE_NAMES, canonicalize, read_protection

ENGINE = None
SEEDS = (0, 1, 42, 0xffffffffffffffff)


def payload_location(items):
    for index, (kind, data) in enumerate(items):
        if kind == 0:
            size, begin = g1.read_uleb(data, 0)
            if data[begin:begin + size] == COMMON_NAME:
                return index, bytearray(data[begin + size:])
    raise AssertionError("missing common protection section")


def replace_payload(items, payload):
    index, _ = payload_location(items)
    changed = list(items)
    changed[index] = (0, g1.uleb(len(COMMON_NAME)) + COMMON_NAME + payload)
    return g1.module_bytes(changed)


class G2Tests(unittest.TestCase):
    command = g1.G1Tests.command
    compile = g1.G1Tests.compile
    values = g1.G1Tests.values
    rejected = g1.G1Tests.rejected

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="walrus-g2-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.ids = itertools.count()
        self.seed = 42

    def protect(self, original, targets=(0, 3), mode="permuted", seed=None, features=()):
        output = self.root / f"protected-{next(self.ids)}.wasm"
        command = [ENGINE, *features]
        if mode is not None:
            command += ["--protection-mode", mode]
        if mode == "permuted":
            command += ["--seed", self.seed if seed is None else seed]
        for index in targets:
            command += ["--protect-function", index]
        result = self.command(*command, "--output", output, original)
        self.assertEqual(result.returncode, 0, result.stderr)
        validation_flags = ["--enable-tail-call"] if "--enable-web-assembly3" in features else []
        result = self.command("wasm-validate", *validation_flags, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def test_pilot_multiple_seeds_and_unchanged_standard_sections(self):
        original = self.compile(names=True)
        baseline = self.protect(original, mode="identity")
        legacy = self.protect(original, mode=None)
        self.assertEqual(self.values(original), g1.EXPECTED)
        self.assertEqual(self.values(baseline), g1.EXPECTED)
        self.assertEqual(read_protection(legacy.read_bytes())["format_version"], 1)
        baseline_sections = [(kind, data) for kind, data in g1.sections(baseline.read_bytes()) if kind]
        for seed in SEEDS:
            with self.subTest(seed=seed):
                output = self.protect(original, seed=seed)
                self.assertEqual(self.values(output), g1.EXPECTED)
                self.assertEqual(output.stat().st_size, baseline.stat().st_size)
                self.assertEqual([(kind, data) for kind, data in g1.sections(output.read_bytes()) if kind],
                                 baseline_sections)
                protection = read_protection(output.read_bytes())
                self.assertEqual((protection["group"], protection["seed"]), ("G2", seed))
                for function in protection["functions"]:
                    self.assertEqual(sorted(function["opcode_map"]), list(range(46)))
                    self.assertNotEqual(function["opcode_map"], list(range(46)))
        old_bodies = g1.bodies(g1.sections(original.read_bytes()))
        new_bodies = g1.bodies(baseline_sections)
        for index, body in enumerate(new_bodies):
            self.assertEqual(body, b"\x00\x00\x0b" if index in (0, 3) else old_bodies[index])

    def test_reproducibility_function_identity_and_seed_variation(self):
        original = self.compile()
        first = self.protect(original, seed=42)
        again = self.protect(original, (3, 0), seed=42)
        self.assertEqual(first.read_bytes(), again.read_bytes())
        different = self.protect(original, seed=43)
        before = read_protection(first.read_bytes())
        after = read_protection(different.read_bytes())
        self.assertNotEqual(first.read_bytes(), different.read_bytes())
        self.assertNotEqual(before["functions"][0]["opcode_map"], before["functions"][1]["opcode_map"])
        for a, b in zip(before["functions"], after["functions"]):
            self.assertNotEqual(a["opcode_map"], b["opcode_map"])
        only_sum = read_protection(self.protect(original, (3,), seed=42).read_bytes())
        self.assertEqual(before["functions"][1]["opcode_map"], only_sum["functions"][0]["opcode_map"])

    def test_algorithm_one_known_vector(self):
        # Fixed Wasm bytes and a protocol vector independent of lowering/build optimization.
        original = self.root / "vector.wasm"
        original.write_bytes(bytes.fromhex(
            "0061736d010000000105016000017f030201000707010372756e00000a0601040041070b"))
        output = self.protect(original, (0,), seed=42)
        protection = read_protection(output.read_bytes())
        self.assertEqual(protection["input_identity_fnv64"], "a53274bcac33ddbb")
        digest = hashlib.sha256(struct.pack("<46H", *protection["functions"][0]["opcode_map"])).hexdigest()
        self.assertEqual(digest, "c24f0be4a5366f8cd46096a6190d64485a5278389ae5fc05341c87010128dca3")
        self.assertEqual(self.values(output, "run"), ["7"])

    def test_canonical_recovery_matches_g1_without_original_input(self):
        original = self.compile()
        baseline = read_protection(self.protect(original, mode="identity").read_bytes())
        for seed in SEEDS:
            output = self.protect(original, seed=seed)
            protection = read_protection(output.read_bytes())
            decoded = recover(output.read_bytes())
            self.assertEqual(decoded["instruction_mapping_coverage"], 1.0)
            self.assertEqual(decoded["recovered_instruction_count"],
                             sum(f["instruction_count"] for f in baseline["functions"]))
            for plain, permuted, restored in zip(baseline["functions"], protection["functions"], decoded["functions"]):
                self.assertEqual(canonicalize(permuted), plain["instructions"])
                self.assertEqual(restored["canonical_stream_sha256"], hashlib.sha256(plain["instructions"]).hexdigest())
        # CLI gets only the deployed artifact, not the original or the seed manifest.
        result = self.command(sys.executable, RESEARCH / "decode_protected.py", output, "--summary")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["instruction_mapping_coverage"], 1.0)

    def test_integer_boundaries_and_function_name_independence(self):
        for seed in SEEDS:
            with self.subTest(seed=seed):
                self.seed = seed
                g1.G1Tests.test_multiple_inputs_and_function_names(self)
                g1.G1Tests.test_packed_locals_multiple_parameters_and_integer_operations(self)

    def test_all_supported_binary_and_unary_semantics(self):
        definitions, wrappers, expected, targets = [], [], [], []
        binary = ("add", "sub", "mul", "and", "or", "xor", "eq", "ne",
                  "lt_s", "lt_u", "gt_s", "gt_u", "le_s", "le_u", "ge_s", "ge_u")
        for width in (32, 64):
            mask = (1 << width) - 1
            a, b = -9, 7
            ua, ub = a & mask, b & mask
            for operation in binary:
                index = len(definitions)
                comparison = operation not in binary[:6]
                result_type = "i32" if comparison else f"i{width}"
                definitions.append(f"(func $f{index} (param i{width} i{width}) (result {result_type}) "
                                   f"local.get 0 local.get 1 i{width}.{operation})")
                wrappers.append(f'(func (export "b{index}") (result {result_type}) '
                                f'i{width}.const {a} i{width}.const {b} call $f{index})')
                if operation in ("eq", "ne"):
                    value = int(a == b) if operation == "eq" else int(a != b)
                elif comparison:
                    left, right = (ua, ub) if operation.endswith("_u") else (a, b)
                    relation = operation[:2]
                    value = int({"lt": left < right, "gt": left > right,
                                 "le": left <= right, "ge": left >= right}[relation])
                else:
                    value = {"add": ua + ub, "sub": ua - ub, "mul": ua * ub,
                             "and": ua & ub, "or": ua | ub, "xor": ua ^ ub}[operation] & mask
                    if value >= 1 << (width - 1):
                        value -= 1 << width
                expected.append(str(value))
                targets.append(index)
        unary = (("i32", "i32", "i32.eqz", 0, 1), ("i64", "i32", "i64.eqz", 0, 1),
                 ("i64", "i32", "i32.wrap_i64", 4294967301, 5),
                 ("i32", "i64", "i64.extend_i32_u", -9, 4294967287),
                 ("i32", "i64", "i64.extend_i32_s", -9, -9))
        for input_type, result_type, operation, value, answer in unary:
            index = len(definitions)
            definitions.append(f"(func $f{index} (param {input_type}) (result {result_type}) local.get 0 {operation})")
            wrappers.append(f'(func (export "u{index}") (result {result_type}) {input_type}.const {value} call $f{index})')
            expected.append(str(answer))
            targets.append(index)
        # Force an i64 local copy whose source is subsequently overwritten.
        index = len(definitions)
        definitions.append(f"(func $f{index} (param i64) (result i64) (local i64) "
                           "local.get 0 local.set 1 i64.const 0 local.set 0 local.get 1)")
        wrappers.append(f'(func (export "copy64") (result i64) i64.const -9 call $f{index})')
        expected.append("-9")
        targets.append(index)
        # Uncalled trap verifies conversion/validation without interrupting other exports.
        targets.append(len(definitions))
        definitions.append("(func unreachable)")
        original = self.compile("(module " + " ".join(definitions + wrappers) + ")")
        self.assertEqual(self.values(original), expected)
        seen_opcodes = set()
        for seed in (0, 42):
            output = self.protect(original, targets, seed=seed)
            self.assertEqual(self.values(output), expected)
            for function in recover(output.read_bytes())["functions"]:
                seen_opcodes.update(function["opcode_counts"])
        pilot = self.protect(self.compile(), seed=42)
        for function in recover(pilot.read_bytes())["functions"]:
            seen_opcodes.update(function["opcode_counts"])
        self.assertEqual(seen_opcodes, set(OPCODE_NAMES))

    def test_call_return_recursive_caller_and_mapping_isolation(self):
        source = """(module
          (func $a (param i32) (result i32) local.get 0 i32.const 1 i32.add)
          (func $b (param i32) (result i32) local.get 0 i32.const 2 i32.mul)
          (func $walk (param i32) (result i32)
            local.get 0 i32.eqz if (result i32) i32.const 0 else
              local.get 0 call $a local.get 0 call $b i32.add
              local.get 0 i32.const 1 i32.sub call $walk i32.add end)
          (func (export "run") (result i32) i32.const 20 call $walk))"""
        original = self.compile(source)
        self.assertEqual(self.values(original, "run"), ["650"])
        for seed in SEEDS:
            self.assertEqual(self.values(self.protect(original, (0, 1), seed=seed), "run"), ["650"])

    def test_indirect_call_initializers_and_tail_call(self):
        g1.G1Tests.test_indirect_call_from_an_unprotected_function(self)
        g1.G1Tests.test_data_global_initializers_and_synthetic_target_rejection(self)
        original = self.compile("""(module
          (func $f (param i32) (result i32) local.get 0 i32.const 3 i32.add)
          (func (export "run") (result i32) i32.const 20 return_call $f))""",
                                features=("--enable-tail-call",))
        output = self.protect(original, (0,), features=("--enable-web-assembly3",))
        result = self.command(ENGINE, "--enable-web-assembly3", "--run-export", "run", output)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "23"), result.stderr)

    def test_void_and_trap_and_changed_body(self):
        g1.G1Tests.test_void_return_and_unreachable_trap(self)
        g1.G1Tests.test_changed_body_changes_bytecode_and_result(self)

    def test_malformed_permutations_and_common_header(self):
        output = self.protect(self.compile())
        items = g1.sections(output.read_bytes())
        _, payload = payload_location(items)
        _, _, count, mapping, stream = g1.record_layout(payload, 48)
        cases = []
        def mutation(offset, fmt, value, message):
            changed = bytearray(payload)
            struct.pack_into(fmt, changed, offset, value)
            cases.append((changed, message))
        mutation(4, "<I", 1, "version")
        mutation(24, "<I", 2, "mode")
        mutation(28, "<I", 99, "algorithm")
        mutation(mapping, "<H", 65535, "out of range")
        mutation(mapping + 2, "<H", struct.unpack_from("<H", payload, mapping)[0], "duplicate opcode")
        mutation(stream, "<H", 65535, "opcode")
        mutation(stream + 2, "<H", 1, "reserved")
        mutation(stream + 12, "<I", 0xffffffff, "frame access")
        # Find a branch using the deployed mapping, not raw opcode numbers.
        decoded_map = struct.unpack_from("<46H", payload, mapping)
        for index in range(count):
            offset = stream + index * 24
            encoded = struct.unpack_from("<H", payload, offset)[0]
            if decoded_map[encoded] in (4, 5, 6):
                mutation(offset + 16, "<Q", count, "branch target")
                break
        else:
            self.fail("fixture should include a branch")
        identity_map = bytearray(payload)
        struct.pack_into("<46H", identity_map, mapping, *range(46))
        cases.extend(((identity_map, "non-identity"), (payload[:-1], "instruction count"),
                      (payload + b"x", "trailing")))
        for changed, message in cases:
            with self.subTest(message=message):
                self.rejected(replace_payload(items, changed), message)
        legacy = self.protect(self.compile(), mode=None)
        legacy_custom = next((kind, data) for kind, data in g1.sections(legacy.read_bytes()) if kind == 0)
        self.rejected(g1.module_bytes(items + [legacy_custom]), "duplicate protection section")

    def test_explicit_identity_mode_is_strict(self):
        output = self.protect(self.compile(), mode="identity")
        items = g1.sections(output.read_bytes())
        _, payload = payload_location(items)
        _, _, _, mapping, _ = g1.record_layout(payload, 48)
        changed = bytearray(payload)
        struct.pack_into("<2H", changed, mapping, 1, 0)
        self.rejected(replace_payload(items, changed), "identity")
        changed = bytearray(payload)
        struct.pack_into("<Q", changed, 32, 1)
        self.rejected(replace_payload(items, changed), "seed")

    def test_cli_seed_and_mode_errors_and_already_protected(self):
        original = self.compile()
        invalid = [("--protection-mode", "permuted"), ("--seed", "1"),
                   ("--protection-mode", "identity", "--seed", "0"),
                   ("--protection-mode", "unknown"), ("--seed", "-1"),
                   ("--protection-mode", "permuted", "--seed", "18446744073709551616"),
                   ("--protection-mode", "permuted", "--seed", "1", "--seed", "2"),
                   ("--protection-mode", "identity", "--protection-mode", "identity")]
        for flags in invalid:
            with self.subTest(flags=flags):
                output = self.root / f"bad-cli-{next(self.ids)}.wasm"
                result = self.command(ENGINE, *flags, "--protect-function", 3, "--output", output, original)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
        protected = self.protect(original)
        result = self.command(ENGINE, "--protection-mode", "permuted", "--seed", 42,
                              "--protect-function", 3, "--output", self.root / "again.wasm", protected)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already protected", result.stderr)

    def test_manifest_measurement_and_group_validation(self):
        original = self.compile()
        output = self.root / "manifest.wasm"
        command = (sys.executable, RESEARCH / "protect.py", "--engine", ENGINE, "--input", original,
                   "--output", output, "--function", 3, "--mode", "permuted", "--seed", 42)
        result = self.command(*command)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(Path(str(output) + ".manifest.json").read_text())
        self.assertEqual(manifest["input_sha256"], hashlib.sha256(original.read_bytes()).hexdigest())
        self.assertEqual(manifest["output_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(manifest["protected_function_indices"], [3])
        self.assertEqual(manifest["protection"]["seed"], 42)
        again = self.command(*command)
        self.assertNotEqual(again.returncode, 0)
        for group in ("G0", "G1"):
            result = self.command(sys.executable, RESEARCH / "measure.py", "--group", group, "--engine", ENGINE,
                                  "--wasm", output, "--out-dir", self.root / "wrong-group")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stderr)
            self.assertFalse((self.root / "wrong-group").exists())
        log_dir = self.root / "measurement"
        result = self.command(sys.executable, RESEARCH / "measure.py", "--group", "G2", "--engine", ENGINE,
                              "--wasm", output, "--export", "sum_1000", "--runs", 2, "--warmups", 0,
                              "--out-dir", log_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        saved = json.loads((log_dir / "metadata.json").read_text())
        self.assertEqual(saved["protection"]["seed"], 42)
        self.assertEqual(json.loads((log_dir / "summary.json").read_text())["runs"], 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    ENGINE = args.engine.resolve(strict=True)
    g1.ENGINE = ENGINE
    unittest.main(argv=[__file__, *remaining], verbosity=2)
