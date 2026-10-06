#!/usr/bin/env python3
"""G3 fusion: semantic oracles, control-flow safety, profiling and exact expansion."""
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
import run_g2_tests as g2

RESEARCH = Path(__file__).resolve().parents[2] / "tools" / "research"
sys.path.insert(0, str(RESEARCH))
from decode_protected import recover
from protected_format import canonicalize, expand, read_protection

ENGINE = None


def layout(payload, offset=56):
    _, _, params, results, count, mapping_count = struct.unpack_from("<6I", payload, offset)
    mapping = offset + 36 + params + results
    return count, mapping, mapping + 2 * mapping_count


class G3Tests(unittest.TestCase):
    command = g1.G1Tests.command
    compile = g1.G1Tests.compile
    values = g1.G1Tests.values
    rejected = g1.G1Tests.rejected
    test_integer_boundaries_and_function_name_independence = g2.G2Tests.test_integer_boundaries_and_function_name_independence
    test_all_supported_binary_and_unary_semantics = g2.G2Tests.test_all_supported_binary_and_unary_semantics
    test_recursive_caller_and_mapping_isolation = g2.G2Tests.test_call_return_recursive_caller_and_mapping_isolation
    test_indirect_initializers_and_tail_call = g2.G2Tests.test_indirect_call_initializers_and_tail_call
    test_void_trap_and_changed_body = g2.G2Tests.test_void_and_trap_and_changed_body

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="walrus-g3-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.ids = itertools.count()
        self.seed = 42

    def protect(self, original, targets=(0, 3), mode="permuted", seed=None, features=(), fusion="on"):
        output = self.root / f"protected-{next(self.ids)}.wasm"
        args = [ENGINE, *features, "--protection-mode", mode, "--fusion", fusion]
        if mode == "permuted":
            args += ["--seed", self.seed if seed is None else seed]
        for index in targets:
            args += ["--protect-function", index]
        result = self.command(*args, "--output", output, original)
        self.assertEqual(result.returncode, 0, result.stderr)
        flags = ["--enable-tail-call"] if "--enable-web-assembly3" in features else []
        result = self.command("wasm-validate", *flags, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def test_pilot_fusion_and_shared_format_expansion(self):
        original = self.compile(names=True)
        for seed in g2.SEEDS:
            with self.subTest(seed=seed):
                plain = self.protect(original, seed=seed, fusion="off")
                fused = self.protect(original, seed=seed)
                self.assertEqual(self.values(fused), g1.EXPECTED)
                self.assertEqual(self.values(plain), g1.EXPECTED)
                a, b = read_protection(plain.read_bytes()), read_protection(fused.read_bytes())
                self.assertEqual((a["group"], b["group"], b["format_version"]), ("G2", "G3", 3))
                self.assertEqual([(k, v) for k, v in g1.sections(plain.read_bytes()) if k],
                                 [(k, v) for k, v in g1.sections(fused.read_bytes()) if k])
                for before, after in zip(a["functions"], b["functions"]):
                    self.assertEqual(before["opcode_map"], after["opcode_map"])
                    self.assertEqual(canonicalize(before), expand(after)[0])
                sum_function = b["functions"][1]
                self.assertEqual((sum_function["original_instruction_count"], sum_function["instruction_count"],
                                  sum_function["fused_instruction_count"]), (11, 9, 2))
                self.assertEqual(sum_function["fusion_patterns"], {"I32AddMoveI32": 1, "I64ExtendI32UAddI64": 1})
                self.assertEqual(plain.stat().st_size - fused.stat().st_size, 48)
                before_hashes = [f["canonical_stream_sha256"] for f in recover(plain.read_bytes())["functions"]]
                after = recover(fused.read_bytes())
                self.assertEqual(before_hashes, [f["canonical_stream_sha256"] for f in after["functions"]])
                self.assertEqual(after["instruction_mapping_coverage"], 1.0)

    def test_reproducibility_and_legacy_recovery(self):
        original = self.compile()
        first = self.protect(original)
        self.assertEqual(first.read_bytes(), self.protect(original, (3, 0)).read_bytes())
        self.assertNotEqual(first.read_bytes(), self.protect(original, seed=43).read_bytes())
        solo = read_protection(self.protect(original, (3,)).read_bytes())["functions"][0]
        self.assertEqual(solo["opcode_map"], read_protection(first.read_bytes())["functions"][1]["opcode_map"])
        identity = self.protect(original, mode="identity", fusion="off")
        self.assertEqual(self.values(identity), g1.EXPECTED)
        self.assertEqual(read_protection(identity.read_bytes())["group"], "G1")
        for legacy_mode in (None, "identity", "permuted"):
            legacy = g2.G2Tests.protect(self, original, mode=legacy_mode)
            self.assertEqual(self.values(legacy), g1.EXPECTED)
            self.assertEqual([f["canonical_stream_sha256"] for f in recover(legacy.read_bytes())["functions"]],
                             [f["canonical_stream_sha256"] for f in recover(first.read_bytes())["functions"]])

    def test_fusion_pass_branch_entry_and_relocation(self):
        repository = Path(__file__).resolve().parents[2]
        binary = self.root / "fusion-pass-test"
        result = self.command("c++", "-std=c++11", "-I" + str(repository / "src"),
                              repository / "test/protected/fusion_pass_test.cpp",
                              repository / "src/parser/ProtectedFusion.cpp", "-o", binary)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command(binary)
        self.assertEqual(result.returncode, 0, result.stderr)

    def manual(self, template, instructions, fusion):
        """Construct public-format fixtures with frame layouts chosen independently of lowering."""
        items = g1.sections(template.read_bytes())
        _, old = g2.payload_location(items)
        function = read_protection(template.read_bytes())["functions"][0]
        mapping = function["opcode_map"]
        encoded = {opcode: index for index, opcode in enumerate(mapping)}
        fused = sum(fields[0] >= 46 for fields in instructions)
        header = bytearray(old[:56])
        struct.pack_into("<I", header, 48, int(fusion))
        record = struct.pack("<9I", 0, 64, 0, 1, len(instructions), 48, len(instructions) + fused, fused, 0)
        record += b"\x7e" + struct.pack("<48H", *mapping)
        stream = b"".join(struct.pack("<HHIIIQ", encoded[op], 0, a, b, dst, imm)
                          for op, a, b, dst, imm in instructions)
        output = self.root / f"manual-{next(self.ids)}.wasm"
        output.write_bytes(g2.replace_payload(items, header + record + stream))
        return output

    def test_frame_aliases_intermediate_liveness_and_wrapping(self):
        template = self.protect(self.compile('(module (func (export "run") (result i64) i64.const 0))'), (0,))
        # i32 writes must preserve the upper half of a pre-existing i64 slot.
        cases = []
        init = [(1, 0, 0, 16, 0x1234567800000000), (0, 0, 0, 0, 0xfffffffe), (0, 0, 0, 8, 3)]
        cases.append((init + [(9, 0, 8, 16, 0), (2, 16, 0, 24, 0), (7, 16, 0, 0, 0)],
                      init + [(46, 0, 8, 16, 24), (7, 16, 0, 0, 0)], 0x1234567800000001))
        # Input is the upper i32 half of the temporary; the add's other operand is the same slot.
        init = [(1, 0, 0, 16, 0xffffffff00000007)]
        for result_slot, expected in ((16, 0xffffffff), (24, 2 * 0xffffffff)):
            cases.append((init + [(44, 20, 0, 16, 0), (25, 16, 16, 24, 0), (7, result_slot, 0, 0, 0)],
                          init + [(47, 20, 16, 24, 16), (7, result_slot, 0, 0, 0)], expected))
        # The temporary overlaps the i32 input; read the other operand after overwriting the slot.
        init = [(1, 0, 0, 8, 0xabcdef01fffffffe)]
        cases.append((init + [(44, 8, 0, 8, 0), (25, 8, 8, 16, 0), (7, 16, 0, 0, 0)],
                      init + [(47, 8, 8, 16, 8), (7, 16, 0, 0, 0)], 2 * 0xfffffffe))
        # Preserve the reverse operand order and unsigned i64 wraparound.
        init = [(0, 0, 0, 0, 0xffffffff), (1, 0, 0, 8, 0xffffffffffffffff)]
        cases.append((init + [(44, 0, 0, 16, 0), (25, 8, 16, 24, 0), (7, 24, 0, 0, 0)],
                      init + [(47, 0, 8, 24, (1 << 32) | 16), (7, 24, 0, 0, 0)], 0xfffffffe))
        for basic, fused, expected in cases:
            with self.subTest(expected=expected):
                a, b = self.manual(template, basic, False), self.manual(template, fused, True)
                self.assertEqual(self.values(a, "run"), [str(expected)])
                self.assertEqual(self.values(b, "run"), [str(expected)])
                self.assertEqual(expand(read_protection(b.read_bytes())["functions"][0])[0],
                                 canonicalize(read_protection(a.read_bytes())["functions"][0]))

    def test_no_candidates_remain_valid_and_report_zero(self):
        original = self.compile('(module (func (export "run") (result i32) i32.const 7))')
        output = self.protect(original, (0,))
        function = read_protection(output.read_bytes())["functions"][0]
        self.assertEqual(function["fused_instruction_count"], 0)
        self.assertEqual(function["instruction_count"], function["original_instruction_count"])
        self.assertEqual(self.values(output, "run"), ["7"])

    def test_malformed_fusion_records_are_rejected(self):
        output = self.protect(self.compile(), (3,))
        items = g1.sections(output.read_bytes())
        _, payload = g2.payload_location(items)
        count, mapping, stream = layout(payload)
        cases = []
        def mutation(offset, fmt, value, message):
            changed = bytearray(payload)
            struct.pack_into(fmt, changed, offset, value)
            cases.append((changed, message))
        mutation(48, "<I", 2, "fusion mode")
        mutation(52, "<I", 2, "fusion algorithm")
        mutation(48, "<I", 0, "fusion mode")
        mutation(56 + 24, "<I", 123, "original instruction count")
        mutation(56 + 28, "<I", 123, "fused instruction count")
        mutation(56 + 32, "<I", 0xffffffff, "skipped fusion count")
        mutation(56 + 20, "<I", 46, "mapping size")
        mutation(mapping, "<H", 48, "out of range")
        mutation(stream, "<H", 48, "opcode")
        decoder = struct.unpack_from("<48H", payload, mapping)
        for pc in range(count):
            offset = stream + pc * 24
            op = decoder[struct.unpack_from("<H", payload, offset)[0]]
            if op == 46:
                mutation(offset + 16, "<Q", 1 << 32, "fused move immediate")
                mutation(offset + 16, "<Q", 3, "frame access")
            if op == 47:
                mutation(offset + 16, "<Q", 1 << 33, "fused extend immediate")
                mutation(offset + 16, "<Q", 4, "frame access")
            if op in (4, 5, 6):
                mutation(offset + 16, "<Q", count, "branch target")
        cases += [(payload[:-1], "instruction count"), (payload + b"x", "trailing")]
        for changed, message in cases:
            with self.subTest(message=message):
                self.rejected(g2.replace_payload(items, changed), message)

    def test_cli_rejects_invalid_combinations(self):
        original = self.compile()
        invalid = [("--fusion", "on"), ("--fusion", "invalid"),
                   ("--fusion", "off", "--fusion", "on"),
                   ("--protection-mode", "identity", "--fusion", "on"),
                   ("--profile-protected",)]
        for flags in invalid:
            output = self.root / f"bad-{next(self.ids)}.wasm"
            result = self.command(ENGINE, *flags, "--protect-function", 3, "--output", output, original)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
        result = self.command(ENGINE, "--profile-protected", original)
        self.assertNotEqual(result.returncode, 0)
        result = self.command(ENGINE, "--run-export", "sum_1000", self.protect(original, (3,)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("WALRUS_PROTECTED_PROFILE", result.stderr)

    def test_profile_manifest_measurement_and_recovery_tools(self):
        original = self.compile()
        for fusion, group, expected_dispatch in (("off", "G2", 7006), ("on", "G3", 5006)):
            output = self.root / f"tool-{fusion}.wasm"
            result = self.command(sys.executable, RESEARCH / "protect.py", "--engine", ENGINE,
                                  "--input", original, "--output", output, "--function", 3,
                                  "--mode", "permuted", "--seed", 42, "--fusion", fusion)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(Path(str(output) + ".manifest.json").read_text())
            self.assertEqual(manifest["protection"]["group"], group)
            profile = self.root / f"profile-{fusion}.json"
            result = self.command(sys.executable, RESEARCH / "profile_protected.py", "--engine", ENGINE,
                                  "--wasm", output, "--export", "sum_1000", "--output", profile)
            self.assertEqual(result.returncode, 0, result.stderr)
            totals = json.loads(profile.read_text())["totals"]
            self.assertEqual(totals["dispatch_count"], expected_dispatch)
            self.assertEqual(totals["semantic_instruction_count"], 7006)
            log = self.root / f"measure-{fusion}"
            result = self.command(sys.executable, RESEARCH / "measure.py", "--group", group, "--engine", ENGINE,
                                  "--wasm", output, "--export", "sum_1000", "--runs", 2, "--warmups", 0, "--out-dir", log)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((log / "summary.json").read_text())["measurement"], "end_to_end_process")
            wrong = self.command(sys.executable, RESEARCH / "measure.py", "--group", "G1", "--engine", ENGINE,
                                 "--wasm", output, "--out-dir", self.root / "wrong")
            self.assertNotEqual(wrong.returncode, 0)
            self.assertFalse((self.root / "wrong").exists())
            decoded = self.command(sys.executable, RESEARCH / "decode_protected.py", output)
            self.assertEqual(decoded.returncode, 0, decoded.stderr)
            self.assertEqual(json.loads(decoded.stdout)["recovered_instruction_count"], 11)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    ENGINE = args.engine.resolve(strict=True)
    g1.ENGINE = g2.ENGINE = ENGINE
    unittest.main(argv=[__file__, *remaining], verbosity=2)
