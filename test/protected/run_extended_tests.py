#!/usr/bin/env python3
"""Protected v4: integer oracles, memory/global effects, calls and malformed payloads."""
import argparse
import itertools
import json
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest

import run_g1_tests as g1
import run_g2_tests as g2

RESEARCH = Path(__file__).resolve().parents[2] / "tools/research"
sys.path.insert(0, str(RESEARCH))
from decode_protected import recover
from protected_format import OPCODES, OPCODE_NAMES, read_protection

ENGINE = None
SEEDS = (0, 42, 0xffffffffffffffff)


def signed(value, width):
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


def record(payload, offset=56):
    index, frame, params, results, count, maps, original, fused, skipped, aux = struct.unpack_from("<10I", payload, offset)
    mapping = offset + 40 + params + results
    stream = mapping + maps * 2
    auxiliary = stream + count * 24
    return {"index": index, "frame": frame, "count": count, "mapping_count": maps, "map": mapping,
            "stream": stream, "auxiliary": auxiliary, "auxiliary_count": aux,
            "end": auxiliary + aux * 4}


class ExtendedTests(unittest.TestCase):
    command = g1.G1Tests.command
    compile = g1.G1Tests.compile
    values = g1.G1Tests.values

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="walrus-extended-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.ids = itertools.count()

    def protect(self, original, targets=(0,), fusion="on", seed=42, mode="permuted", features=()):
        output = self.root / f"protected-{next(self.ids)}.wasm"
        flags = [ENGINE, *features, "--extended", "--protection-mode", mode, "--fusion", fusion]
        if mode == "permuted": flags += ["--seed", seed]
        for index in targets: flags += ["--protect-function", index]
        result = self.command(*flags, "--output", output, original)
        self.assertEqual(result.returncode, 0, result.stderr)
        validation = ["--enable-multi-memory"] if "--enable-web-assembly3" in features else []
        result = self.command("wasm-validate", *validation, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(read_protection(output.read_bytes())["format_version"], 4)
        return output

    def agree(self, original, expected, targets=(0,), export="*", seeds=SEEDS):
        self.assertEqual(self.values(original, export), expected)
        for seed in seeds:
            for fusion in ("off", "on"):
                with self.subTest(seed=seed, fusion=fusion):
                    output = self.protect(original, targets, fusion, seed)
                    self.assertEqual(self.values(output, export), expected)

    def trap(self, original, message, targets=(0,), export="run"):
        for module in (original, self.protect(original, targets, fusion="off"), self.protect(original, targets)):
            result = self.command(ENGINE, "--run-export", export, module)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn(message, result.stderr)

    def test_integer_binary_oracles_and_shift_boundaries(self):
        rng = random.Random(20261007)
        definitions, wrappers, expected = [], [], []
        operations = ("div_s", "div_u", "rem_s", "rem_u", "shl", "shr_s", "shr_u", "rotl", "rotr")
        for width in (32, 64):
            mask = (1 << width) - 1
            pairs = [(0, 1), (-7, 3), (-(1 << (width - 1)), -1), (-1, width),
                     (1, width + 1), (-(1 << (width - 1)), width - 1), ((1 << (width - 1)) - 1, -3)]
            pairs += [(rng.randrange(-(1 << (width - 1)), 1 << (width - 1)), rng.randrange(1, 100)) for _ in range(8)]
            for operation in operations:
                index = len(definitions)
                definitions.append(f'(func $f{index} (param i{width} i{width}) (result i{width}) local.get 0 local.get 1 i{width}.{operation})')
                for a, b in pairs:
                    if operation == "div_s" and a == -(1 << (width - 1)) and b == -1: continue
                    ua, ub, shift = a & mask, b & mask, b & (width - 1)
                    if operation == "div_s" or operation == "rem_s":
                        q = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
                        value = q if operation == "div_s" else a - q * b
                    elif operation == "div_u": value = ua // ub
                    elif operation == "rem_u": value = ua % ub
                    elif operation == "shl": value = ua << shift
                    elif operation == "shr_s": value = a >> shift
                    elif operation == "shr_u": value = ua >> shift
                    elif operation == "rotl": value = (ua << shift) | (ua >> ((-shift) & (width - 1)))
                    else: value = (ua >> shift) | (ua << ((-shift) & (width - 1)))
                    name = f"v{len(wrappers)}"
                    wrappers.append(f'(func (export "{name}") (result i{width}) i{width}.const {a} i{width}.const {b} call $f{index})')
                    expected.append(str(signed(value, width)))
        original = self.compile("(module " + "\n".join(definitions + wrappers) + ")")
        self.agree(original, expected, tuple(range(len(definitions))))

    def test_integer_unary_oracles(self):
        definitions, wrappers, expected = [], [], []
        for width in (32, 64):
            for operation in ("clz", "ctz", "popcnt", "extend8_s", "extend16_s", *(("extend32_s",) if width == 64 else ())):
                index = len(definitions)
                definitions.append(f'(func $f{index} (param i{width}) (result i{width}) local.get 0 i{width}.{operation})')
                for a in (0, 1, -1, 128, 32768, 0x80000000, -(1 << (width - 1))):
                    ua = a & ((1 << width) - 1)
                    if operation == "clz": value = width - ua.bit_length()
                    elif operation == "ctz": value = width if not ua else (ua & -ua).bit_length() - 1
                    elif operation == "popcnt": value = bin(ua).count("1")
                    else: value = signed(ua, int(operation[6:-2]))
                    wrappers.append(f'(func (export "v{len(wrappers)}") (result i{width}) i{width}.const {a} call $f{index})')
                    expected.append(str(value))
        original = self.compile("(module " + "\n".join(definitions + wrappers) + ")")
        self.agree(original, expected, tuple(range(len(definitions))))

    def test_integer_traps_and_signed_remainder_overflow(self):
        for width in (32, 64):
            for operation in ("div_s", "div_u", "rem_s", "rem_u"):
                original = self.compile(f'(module (func (export "run") (result i{width}) i{width}.const 7 i{width}.const 0 i{width}.{operation}))')
                self.trap(original, "integer divide by zero")
            minimum = -(1 << (width - 1))
            original = self.compile(f'(module (func (export "run") (result i{width}) i{width}.const {minimum} i{width}.const -1 i{width}.div_s))')
            self.trap(original, "integer overflow")
            original = self.compile(f'(module (func (export "run") (result i{width}) i{width}.const {minimum} i{width}.const -1 i{width}.rem_s))')
            self.agree(original, ["0"], export="run")

    def test_select_and_branch_table_with_fusion_recovery(self):
        source = '''(module
          (func $switch (param i32) (result i32) (local i32)
            i32.const 4 i32.const 5 i32.add local.set 1
            block $default block $two block $one block $zero
              local.get 0 br_table $zero $one $two $default
            end local.get 1 i32.const 1 i32.add return
            end local.get 1 i32.const 2 i32.add return
            end local.get 1 i32.const 3 i32.add return
            end local.get 1 i32.const 4 i32.add)
          (func $s32 (param i32) (result i32) i32.const -7 i32.const 8 local.get 0 select)
          (func $s64 (param i32) (result i64) i64.const -9 i64.const 10 local.get 0 select)
        '''
        expected = []
        for i, value in enumerate((0, 1, 2, 3, -1)):
            source += f'(func (export "b{i}") (result i32) i32.const {value} call $switch)'
            expected.append(str(10 + i if i < 3 else 13))
        for name, result_type, yes, no in (("s32", "i32", -7, 8), ("s64", "i64", -9, 10)):
            for i, value in enumerate((0, -1)):
                source += f'(func (export "{name}-{i}") (result {result_type}) i32.const {value} call ${name})'
                expected.append(str(yes if value else no))
        original = self.compile(source + ")")
        self.agree(original, expected, (0, 1, 2))
        plain = recover(self.protect(original, (0, 1, 2), fusion="off").read_bytes())
        fused = recover(self.protect(original, (0, 1, 2)).read_bytes())
        self.assertEqual([f["canonical_program_sha256"] for f in plain["functions"]],
                         [f["canonical_program_sha256"] for f in fused["functions"]])
        self.assertIn("BrTable", plain["functions"][0]["opcode_counts"])

    def test_integer_memory_widths_offsets_and_sign_extension(self):
        definitions, wrappers, expected = [], [], []
        for width in (32, 64):
            sizes = (8, 16, width) if width == 32 else (8, 16, 32, 64)
            for bits in sizes:
                for sign in (("s", "u") if bits < width else ("",)):
                    index = len(definitions)
                    store = "store" if bits == width else f"store{bits}"
                    load = "load" if bits == width else f"load{bits}_{sign}"
                    # Different addends address the same unaligned byte range.
                    definitions.append(f'''(func $f{index} (param i{width}) (result i{width})
                      i32.const 1 local.get 0 i{width}.{store} offset=4 align=1
                      i32.const 3 i{width}.{load} offset=2 align=1)''')
                    wrappers.append(f'(func (export "v{index}") (result i{width}) i{width}.const -129 call $f{index})')
                    value = (-129) & ((1 << bits) - 1)
                    expected.append(str(signed(value, bits) if sign == "s" or bits == width else value))
        original = self.compile("(module (memory 1) " + "\n".join(definitions + wrappers) + ")")
        self.agree(original, expected, tuple(range(len(definitions))))
        names = set()
        for function in recover(self.protect(original, tuple(range(len(definitions)))).read_bytes())["functions"]:
            names.update(function["opcode_counts"])
        self.assertTrue({name for name in OPCODE_NAMES if name.startswith("I") and ("Load" in name or "Store" in name)} <= names)

    def test_memory_zero_offset_bounds_and_address_overflow(self):
        original = self.compile('''(module (memory 1)
          (func (export "run") (result i64)
            i32.const 7 i64.const -123 i64.store align=1
            i32.const 7 i64.load align=1))''')
        self.agree(original, ["-123"], export="run")
        for body in ("i32.const 65533 i32.load", "i32.const -1 i32.load offset=1",
                     "i32.const 65535 i32.const 3 i32.store16 i32.const 0"):
            self.trap(self.compile(f'(module (memory 1) (func (export "run") (result i32) {body}))'), "out of bounds")

    def test_global_and_memory_effects_visible_to_unprotected_callers(self):
        original = self.compile('''(module (memory 1)
          (global $a (mut i32) (i32.const 5)) (global $b (mut i64) (i64.const 7))
          (func $write (param i32 i64)
            local.get 0 global.set $a local.get 1 global.set $b
            i32.const 1 local.get 0 i32.store align=1)
          (func $read (result i64)
            global.get $a i64.extend_i32_s global.get $b i64.add)
          (func (export "run") (result i64)
            i32.const -9 i64.const 12 call $write
            i32.const 1 i32.load align=1 i64.extend_i32_s call $read i64.add)
          (func (export "state") (result i64) global.get $b))''')
        self.agree(original, ["-6", "12"], (0, 1))

    def test_memory_size_growth_success_failure_and_refreshed_buffer(self):
        original = self.compile('''(module (memory 1 2)
          (func (export "run") (result i32) (local i32)
            i32.const 0 i32.const 17 i32.store
            i32.const 1 memory.grow local.set 0
            i32.const 65536 i32.const 23 i32.store
            local.get 0 memory.size i32.add
            i32.const 0 i32.load i32.add i32.const 65536 i32.load i32.add
            i32.const 1 memory.grow i32.add))''')
        self.agree(original, ["42"], export="run")

    def test_direct_calls_protected_and_unprotected_recursion(self):
        original = self.compile('''(module
          (func $gcd (param i32 i32) (result i32)
            local.get 1 i32.eqz if (result i32) local.get 0
            else local.get 1 local.get 0 local.get 1 i32.rem_u call $gcd end)
          (func $factorial (param i64) (result i64)
            local.get 0 i64.const 1 i64.le_u if (result i64) i64.const 1
            else local.get 0 local.get 0 i64.const 1 i64.sub call $factorial i64.mul end)
          (func (export "gcd") (result i32) i32.const 1071 i32.const 462 call $gcd)
          (func (export "factorial") (result i64) i64.const 20 call $factorial))''')
        self.agree(original, ["21", "2432902008176640000"], (0, 1))
        self.agree(original, ["21", "2432902008176640000"], (2, 3), seeds=(42,))
        self.agree(original, ["21", "2432902008176640000"], (0, 1, 2, 3), seeds=(42,))

    def test_mixed_multiple_return_values_and_void_calls(self):
        original = self.compile('''(module (global $g (mut i32) (i32.const 0))
          (func $tuple (param i32) (result i32 i64 i32)
            local.get 0 i64.const -123 i32.const -7)
          (func $update i32.const 9 global.set $g)
          (func (export "run") (result i64) (local i32 i64 i32)
            call $update i32.const -5 call $tuple
            local.set 2 local.set 1 local.set 0
            local.get 0 i64.extend_i32_s local.get 1 i64.add
            local.get 2 i64.extend_i32_s i64.add global.get $g i64.extend_i32_s i64.add)
          (func (export "tuple") (result i32 i64 i32) i32.const -5 call $tuple))''')
        self.agree(original, ["-126", "-5", "-123", "-7"], (0, 1, 2, 3))
        self.agree(original, ["-126", "-5", "-123", "-7"], (0, 1), seeds=(42,))

    def test_call_indirect_and_trap_checks(self):
        source = '''(module (type $t (func (param i32) (result i32)))
          (table 3 funcref)
          (func $f (type $t) local.get 0 i32.const 3 i32.add)
          (func $wrong (result i64) i64.const 7)
          (elem (i32.const 0) $f $wrong)
          (func (export "run") (result i32)
            i32.const 20 i32.const SELECTOR call_indirect (type $t)))'''
        original = self.compile(source.replace("SELECTOR", "0"))
        self.agree(original, ["23"], (0, 2), export="run")
        for selector, message in ((1, "indirect call type mismatch"), (2, "uninitialized element"), (3, "undefined element")):
            self.trap(self.compile(source.replace("SELECTOR", str(selector))), message, (2,))

    def test_call_stack_exhaustion_and_callee_trap_propagation(self):
        original = self.compile('''(module (func $f call $f) (func (export "run") call $f))''')
        self.trap(original, "call stack exhausted", (0, 1))
        original = self.compile('''(module (memory 1) (func $f (result i32) i32.const 65536 i32.load)
          (func (export "run") (result i32) call $f))''')
        self.trap(original, "out of bounds", (0, 1))

    def test_start_function_runs_after_protection_is_bound(self):
        original = self.compile('''(module (global $g (mut i32) (i32.const 0))
          (func $start i32.const 42 global.set $g) (start $start)
          (func (export "run") (result i32) global.get $g))''')
        self.agree(original, ["42"], (0, 1), export="run")

    def test_nop_drop_and_local_tee(self):
        original = self.compile('''(module
          (func $f (param i32) (result i32) (local i32)
            nop i32.const 31 drop local.get 0 local.tee 1 drop
            block $done local.get 0 i32.eqz br_if $done nop end
            local.get 1 i32.const 2 i32.add)
          (func (export "run") (result i32) i32.const 40 call $f))''')
        self.agree(original, ["42"], (0, 1), export="run")

    def test_imported_native_function_and_import_indices(self):
        original = self.compile('''(module
          (import "spectest" "print_i32" (func $print (param i32)))
          (func (export "run") (result i32) i32.const 42 call $print i32.const 7))''')
        for fusion in ("off", "on"):
            output = self.protect(original, (1,), fusion=fusion)
            function = read_protection(output.read_bytes())["functions"][0]
            self.assertEqual(function["index"], 1)
            # The spec shell resolves spectest imports; binary embedding retains the custom section.
            encoded = "".join("\\" + format(byte, "02x") for byte in output.read_bytes())
            script = self.root / f"host-{fusion}.wast"
            script.write_text(f'(module binary "{encoded}")\n(assert_return (invoke "run") (i32.const 7))\n')
            result = self.command(ENGINE, script)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("42 : i32", result.stdout)
            self.assertIn(": OK", result.stdout)

    def test_multiple_memory_indices(self):
        original = self.compile('''(module (memory 1) (memory 1 2)
          (func (export "run") (result i64)
            i32.const 3 i64.const -77 i64.store 1 offset=2 align=1
            i32.const 1 memory.grow 1 drop
            i32.const 5 i64.load 1 align=1
            memory.size 0 i64.extend_i32_u i64.add
            memory.size 1 i64.extend_i32_u i64.add))''', features=("--enable-multi-memory",))
        for fusion in ("off", "on"):
            output = self.protect(original, (0,), fusion=fusion, features=("--enable-web-assembly3",))
            for module in (original, output):
                result = self.command(ENGINE, "--enable-web-assembly3", "--run-export", "run", module)
                self.assertEqual((result.returncode, result.stdout.strip()), (0, "-74"), result.stderr)
        output = self.root / "multiple-memory-manifest.wasm"
        result = self.command(sys.executable, RESEARCH / "protect.py", "--engine", ENGINE, "--input", original,
                              "--output", output, "--function", 0, "--extended", "--mode", "permuted", "--seed", 42,
                              "--enable-web-assembly3")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_branch_tables_global_types_and_call_types(self):
        source = '''(module (type $t (func (result i32))) (table 1 funcref)
          (global $a i32 (i32.const 7)) (global $b (mut i64) (i64.const 9))
          (func $f (type $t) i32.const 42) (elem (i32.const 0) $f)
          (func (export "run") (result i32)
            block $end block $inner i32.const 0 br_table $inner $end end end
            global.get $a drop i32.const 0 call_indirect (type $t)))'''
        output = self.protect(self.compile(source), (1,))
        items = g1.sections(output.read_bytes()); _, payload = g2.payload_location(items)
        loc = record(payload); mapping = struct.unpack_from(f"<{loc['mapping_count']}H", payload, loc["map"])
        cases = []
        call_auxiliary = None
        for pc in range(loc["count"]):
            offset = loc["stream"] + pc * 24
            fields = struct.unpack_from("<HHIIIQ", payload, offset); name = OPCODE_NAMES[mapping[fields[0]]]
            if name == "GlobalGet32":
                changed = bytearray(payload); struct.pack_into("<Q", changed, offset + 16, 1)
                cases.append((changed, "global type mismatch"))
                changed = bytearray(payload); struct.pack_into("<H", changed, offset, mapping.index(OPCODES["GlobalSet32"]))
                struct.pack_into("<I", changed, offset + 4, fields[4]); struct.pack_into("<I", changed, offset + 12, 0)
                cases.append((changed, "immutable"))
            elif name == "BrTable":
                changed = bytearray(payload); struct.pack_into("<I", changed, loc["auxiliary"] + fields[4] * 4, loc["count"])
                cases.append((changed, "branch table target"))
                changed = bytearray(payload); struct.pack_into("<Q", changed, offset + 16, 0xffffffff)
                cases.append((changed, "branch table operands"))
            elif name == "CallIndirect":
                changed = bytearray(payload); struct.pack_into("<Q", changed, offset + 16, 0xffffffff)
                cases.append((changed, "call type index"))
                changed = bytearray(payload); struct.pack_into("<I", changed, offset + 8, 0xffffffff)
                cases.append((changed, "table index"))
        self.assertGreaterEqual(len(cases), 6)
        for changed, message in cases:
            with self.subTest(message=message):
                bad = self.root / f"bad-types-{next(self.ids)}.wasm"; bad.write_bytes(g2.replace_payload(items, changed))
                result = self.command(ENGINE, "--run-export", "run", bad)
                self.assertNotEqual(result.returncode, 0); self.assertIn(message, result.stderr)

    def test_reproducibility_manifest_and_decoding(self):
        original = self.compile()
        a = self.protect(original, (0, 3))
        self.assertEqual(a.read_bytes(), self.protect(original, (3, 0)).read_bytes())
        self.assertNotEqual(a.read_bytes(), self.protect(original, (0, 3), seed=43).read_bytes())
        identity = self.protect(original, (0, 3), mode="identity", fusion="off")
        self.assertEqual(self.values(identity), g1.EXPECTED)
        for output in (a, identity):
            result = self.command(sys.executable, RESEARCH / "decode_protected.py", output, "--summary")
            self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "manifest.wasm"
        result = self.command(sys.executable, RESEARCH / "protect.py", "--engine", ENGINE,
                              "--input", original, "--output", output, "--function", 3,
                              "--mode", "permuted", "--seed", 42, "--fusion", "on", "--extended")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(Path(str(output) + ".manifest.json").read_text())["protection"]["format_version"], 4)

    def test_extended_pilot_and_separate_profiling(self):
        original = self.compile(Path(__file__).with_name("extended-pilot.wat").read_text())
        self.agree(original, ["129", "499500", "21", "500650", "1000"], (0, 1, 2, 3))
        pilot = self.protect(self.compile(), (3,))
        result = self.command(ENGINE, "--profile-protected", "--run-export", "sum_1000", pilot)
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix = "WALRUS_PROTECTED_PROFILE "
        records = [json.loads(line[len(prefix):]) for line in result.stderr.splitlines() if line.startswith(prefix)]
        self.assertEqual(records, [{"function_index": 3, "dispatch_count": 5006,
                                   "semantic_instruction_count": 7006, "fused_dispatch_count": 2000}])

    def test_malformed_operand_tables_and_module_indices(self):
        original = self.compile('''(module (memory 1) (global $g (mut i32) (i32.const 0))
          (func $f (param i32) (result i32) local.get 0 i32.const 1 i32.add)
          (func (export "run") (result i32)
            i32.const 0 i32.const 3 i32.store i32.const 0 i32.load
            global.set $g global.get $g call $f))''')
        output = self.protect(original, (1,))
        items = g1.sections(output.read_bytes()); _, payload = g2.payload_location(items)
        loc = record(payload); mapping = struct.unpack_from(f"<{loc['mapping_count']}H", payload, loc["map"])
        cases = []
        def change(offset, fmt, value, message):
            mutated = bytearray(payload); struct.pack_into(fmt, mutated, offset, value); cases.append((mutated, message))
        change(56 + 36, "<I", 0xffffffff, "auxiliary count")
        for pc in range(loc["count"]):
            offset = loc["stream"] + pc * 24
            fields = struct.unpack_from("<HHIIIQ", payload, offset); name = OPCODE_NAMES[mapping[fields[0]]]
            if name == "Call":
                call_auxiliary = fields[4]
                change(offset + 16, "<Q", 999, "call index")
                change(offset + 12, "<I", 0xffffffff, "auxiliary range")
                change(loc["auxiliary"] + fields[4] * 4, "<I", 3, "frame access")
            elif name.startswith("Global"):
                change(offset + 16, "<Q", 999, "global index")
            elif "Load" in name:
                change(offset + 8, "<I", 999, "memory index")
            elif name == "ReturnMany":
                change(offset + 16, "<Q", 0xffffffff, "auxiliary range")
                if call_auxiliary is not None:
                    change(offset + 16, "<Q", call_auxiliary, "overlapping auxiliary")
        unused = bytearray(payload)
        struct.pack_into("<I", unused, 56 + 36, loc["auxiliary_count"] + 1)
        unused.extend(struct.pack("<I", 0))
        cases.append((unused, "unreferenced auxiliary"))
        cases += [(payload[:-1], "auxiliary count"), (payload + b"x", "trailing")]
        for changed, message in cases:
            with self.subTest(message=message):
                bad = self.root / f"bad-{next(self.ids)}.wasm"; bad.write_bytes(g2.replace_payload(items, changed))
                result = self.command(ENGINE, "--run-export", "run", bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_unsupported_types_and_old_formats_fail_without_output(self):
        for source in ('(module (func (param f64) (result f64) local.get 0))',
                       '(module (func (param v128) (result v128) local.get 0))'):
            original = self.compile(source)
            output = self.root / f"unsupported-{next(self.ids)}.wasm"
            result = self.command(ENGINE, "--extended", "--protect-function", 0, "--output", output, original)
            self.assertNotEqual(result.returncode, 0); self.assertFalse(output.exists())
        original = self.compile('(module (func (result i32) i32.const 7 i32.const 3 i32.div_u))')
        output = self.root / "old-format.wasm"
        result = self.command(ENGINE, "--protect-function", 0, "--output", output, original)
        self.assertNotEqual(result.returncode, 0); self.assertIn("--extended", result.stderr); self.assertFalse(output.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    ENGINE = args.engine.resolve(strict=True)
    g1.ENGINE = g2.ENGINE = ENGINE
    unittest.main(argv=[__file__, *remaining], verbosity=2)
