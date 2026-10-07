#!/usr/bin/env python3
"""Protected v5 scalar floating-point integration and official specification tests."""
import argparse
import itertools
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import run_g1_tests as g1
import run_g2_tests as g2
from run_extended_tests import record

RESEARCH = Path(__file__).resolve().parents[2] / "tools/research"
sys.path.insert(0, str(RESEARCH))
from decode_protected import recover
from protected_format import OPCODE_NAMES, read_protection

ENGINE = None
SEEDS = (0, 42, 0xffffffffffffffff)
SPEC = Path(__file__).resolve().parents[1] / "wasm-spec/core"


def signed(value, width):
    return value - (1 << width) if value >> (width - 1) else value


def float_bits(value, width):
    return int.from_bytes(struct.pack("<f" if width == 32 else "<d", value), "little")


def expression_end(source, start):
    """Find a module boundary while respecting strings and nested WAT comments."""
    depth, pos = 0, start
    while pos < len(source):
        if source.startswith(";;", pos):
            end = source.find("\n", pos)
            pos = len(source) if end < 0 else end + 1
            continue
        if source.startswith("(;", pos):
            comments, pos = 1, pos + 2
            while comments:
                if source.startswith("(;", pos): comments, pos = comments + 1, pos + 2
                elif source.startswith(";)", pos): comments, pos = comments - 1, pos + 2
                else: pos += 1
                if pos > len(source): raise ValueError("unterminated comment")
            continue
        if source[pos] == '"':
            pos += 1
            while pos < len(source) and source[pos] != '"':
                pos += 2 if source[pos] == "\\" else 1
            pos += 1
            continue
        if source[pos] == "(": depth += 1
        elif source[pos] == ")":
            depth -= 1
            if not depth: return pos + 1
        pos += 1
    raise ValueError("unterminated module")


class FloatTests(unittest.TestCase):
    command = g1.G1Tests.command
    compile = g1.G1Tests.compile
    values = g1.G1Tests.values

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="walrus-float-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.ids = itertools.count()

    def protect(self, original, targets=(0,), fusion="on", seed=42, mode="permuted", features=()):
        output = self.root / f"protected-{next(self.ids)}.wasm"
        flags = [ENGINE, *features, "--floating-point", "--protection-mode", mode, "--fusion", fusion]
        if mode == "permuted": flags += ["--seed", seed]
        for index in targets: flags += ["--protect-function", index]
        result = self.command(*flags, "--output", output, original)
        self.assertEqual(result.returncode, 0, result.stderr)
        features = ["--enable-multi-memory"] if "--enable-web-assembly3" in features else []
        result = self.command("wasm-validate", *features, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        protection = read_protection(output.read_bytes())
        self.assertEqual(protection["format_version"], 5)
        self.assertEqual(len(protection["functions"][0]["opcode_map"]), 176)
        return output

    def agree(self, original, expected, targets=(0,), export="*", seeds=SEEDS):
        self.assertEqual(self.values(original, export), expected)
        for seed in seeds:
            for fusion in ("off", "on"):
                with self.subTest(seed=seed, fusion=fusion):
                    output = self.protect(original, targets, fusion, seed)
                    self.assertEqual(self.values(output, export), expected)

    def test_arithmetic_comparisons_and_unary_bit_oracles(self):
        definitions, wrappers, expected = [], [], []
        for width in (32, 64):
            for op, value in (("add", 3.75), ("sub", -0.75), ("mul", 3.375), ("div", 2 / 3),
                              ("min", 1.5), ("max", 2.25), ("copysign", -1.5)):
                index = len(definitions)
                definitions.append(f'(func $f{index} (param f{width} f{width}) (result f{width}) local.get 0 local.get 1 f{width}.{op})')
                b = -2.25 if op == "copysign" else 2.25
                wrappers.append(f'(func (export "v{index}") (result i{width}) f{width}.const 1.5 f{width}.const {b} call $f{index} i{width}.reinterpret_f{width})')
                expected.append(str(signed(float_bits(value, width), width)))
            for op, value in (("eq", 0), ("ne", 1), ("lt", 1), ("le", 1), ("gt", 0), ("ge", 0)):
                index = len(definitions)
                definitions.append(f'(func $f{index} (param f{width} f{width}) (result i32) local.get 0 local.get 1 f{width}.{op})')
                wrappers.append(f'(func (export "v{index}") (result i32) f{width}.const 1.5 f{width}.const 2.25 call $f{index})')
                expected.append(str(value))
            for op, a, value in (("abs", -1.5, 1.5), ("neg", 1.5, -1.5), ("sqrt", 2.25, 1.5),
                                 ("ceil", -1.5, -1), ("floor", -1.5, -2), ("trunc", -1.5, -1),
                                 ("nearest", 2.5, 2), ("nearest", 3.5, 4)):
                index = len(definitions)
                definitions.append(f'(func $f{index} (param f{width}) (result f{width}) local.get 0 f{width}.{op})')
                wrappers.append(f'(func (export "v{index}") (result i{width}) f{width}.const {a} call $f{index} i{width}.reinterpret_f{width})')
                expected.append(str(signed(float_bits(value, width), width)))
        module = self.compile('(module ' + '\n'.join(definitions + wrappers) + ')')
        self.agree(module, expected, tuple(range(len(definitions))))

    def test_nan_payload_zero_and_infinity_bit_transport(self):
        definitions, wrappers, expected = [], [], []
        for width, payloads in ((32, (0, 0x80000000, 0x7f800000, 0xff800000, 0x7fa12345, 0xffc54321)),
                                (64, (0, 0x8000000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff4123456789abc, 0xfff8543212345678))):
            index = len(definitions)
            definitions.append(f'''(func $f{index} (param f{width} f{width} i32) (result f{width}) (local f{width})
              local.get 0 local.set 3 local.get 3 local.get 1 local.get 2 select (result f{width}))''')
            for bits in payloads:
                for condition in (0, 1):
                    other = bits ^ (1 << (width - 1))
                    wrappers.append(f'(func (export "v{len(wrappers)}") (result i{width}) i{width}.const {signed(bits, width)} f{width}.reinterpret_i{width} i{width}.const {signed(other, width)} f{width}.reinterpret_i{width} i32.const {condition} call $f{index} i{width}.reinterpret_f{width})')
                    expected.append(str(signed(bits if condition else other, width)))
        self.agree(self.compile('(module ' + '\n'.join(definitions + wrappers) + ')'), expected, (0, 1))

    def test_conversions_signed_unsigned_and_precision_boundaries(self):
        definitions, wrappers, expected = [], [], []
        for floats in (32, 64):
            for integers in (32, 64):
                for sign in ('s', 'u'):
                    for saturating in ('', '_sat'):
                        index = len(definitions)
                        op = f'i{integers}.trunc{saturating}_f{floats}_{sign}'
                        definitions.append(f'(func $f{index} (param f{floats}) (result i{integers}) local.get 0 {op})')
                        a, value = (-12.75, -12) if sign == 's' else (12.75, 12)
                        wrappers.append(f'(func (export "v{index}") (result i{integers}) f{floats}.const {a} call $f{index})')
                        expected.append(str(value))
                    index = len(definitions)
                    definitions.append(f'(func $f{index} (param i{integers}) (result f{floats}) local.get 0 f{floats}.convert_i{integers}_{sign})')
                    bits = (1 << (integers - 1)) + 7 if sign == 'u' else (1 << (integers - 1)) - 3
                    value = bits if sign == 'u' else signed(bits, integers)
                    wrappers.append(f'(func (export "v{index}") (result i{floats}) i{integers}.const {signed(bits, integers)} call $f{index} i{floats}.reinterpret_f{floats})')
                    expected.append(str(signed(float_bits(float(value), floats), floats)))
        for out, source, value in ((64, 32, 1.5), (32, 64, 1.0000000596046448)):
            index = len(definitions)
            op = 'promote' if out == 64 else 'demote'
            definitions.append(f'(func $f{index} (param f{source}) (result f{out}) local.get 0 f{out}.{op}_f{source})')
            wrappers.append(f'(func (export "v{index}") (result i{out}) f{source}.const {value} call $f{index} i{out}.reinterpret_f{out})')
            expected.append(str(signed(float_bits(value, out), out)))
        self.agree(self.compile('(module ' + '\n'.join(definitions + wrappers) + ')'), expected, tuple(range(len(definitions))))

    def test_integer_conversion_traps_and_saturation(self):
        for floats in (32, 64):
            for integers in (32, 64):
                for sign in ('s', 'u'):
                    limit = (1 << (integers - (sign == 's')))
                    for literal, message in (('nan', 'invalid conversion to integer'), ('inf', 'integer overflow'),
                                             (str(limit), 'integer overflow'), ('-inf', 'integer overflow')):
                        source = self.compile(f'(module (func (export "run") (result i{integers}) f{floats}.const {literal} i{integers}.trunc_f{floats}_{sign}))')
                        for module in (source, self.protect(source, fusion='off'), self.protect(source)):
                            result = self.command(ENGINE, '--run-export', 'run', module)
                            self.assertNotEqual(result.returncode, 0); self.assertIn(message, result.stderr)
                    maximum = (1 << (integers - (sign == 's'))) - 1
                    minimum = -(1 << (integers - 1)) if sign == 's' else 0
                    source = self.compile(f'''(module
                      (func (export "nan") (result i{integers}) f{floats}.const nan i{integers}.trunc_sat_f{floats}_{sign})
                      (func (export "max") (result i{integers}) f{floats}.const inf i{integers}.trunc_sat_f{floats}_{sign})
                      (func (export "min") (result i{integers}) f{floats}.const -inf i{integers}.trunc_sat_f{floats}_{sign}))''')
                    self.agree(source, ['0', str(signed(maximum, integers)), str(minimum)], (0, 1, 2), seeds=(42,))

    def test_memory_and_globals_preserve_nan_bits_and_state(self):
        for width, bits in ((32, 0xffa12345), (64, 0xfff4123456789abc)):
            source = self.compile(f'''(module (memory 1 2) (global $g (mut f{width}) (f{width}.const 0))
              (func $state (param f{width}) (result f{width})
                local.get 0 global.set $g i32.const 1 global.get $g f{width}.store offset=2 align=1
                i32.const 1 memory.grow drop i32.const 3 f{width}.load align=1)
              (func (export "run") (result i{width})
                i{width}.const {signed(bits, width)} f{width}.reinterpret_i{width} call $state i{width}.reinterpret_f{width})
              (func (export "global") (result i{width}) global.get $g i{width}.reinterpret_f{width})
              (func (export "memory") (result i{width}) i32.const 1 i{width}.load offset=2 align=1))''')
            self.agree(source, [str(signed(bits, width))] * 3)

    def test_mixed_calls_recursion_multiple_returns_and_float_exports(self):
        source = self.compile('''(module
          (func $mix (param i32 f32 i64 f64) (result i32 f32 i64 f64)
            local.get 0 i32.const 1 i32.add local.get 1 f32.const 0.5 f32.add
            local.get 2 i64.const 2 i64.add local.get 3 f64.const 0.25 f64.add)
          (func $rec (param i32 f64) (result f64)
            local.get 0 i32.eqz if (result f64) local.get 1 else
              local.get 0 i32.const 1 i32.sub local.get 1 f64.const 0.5 f64.add call $rec end)
          (func (export "mixed") (result i64) (local i32 f32 i64 f64)
            i32.const 3 f32.const 1.5 i64.const 5 f64.const 2.25 call $mix
            local.set 3 local.set 2 local.set 1 local.set 0
            local.get 0 i64.extend_i32_s local.get 1 i64.trunc_f32_s i64.add
            local.get 2 i64.add local.get 3 i64.trunc_f64_s i64.add)
          (func (export "recursive") (result f64) i32.const 10 f64.const 1.25 call $rec)
          (func (export "single") (result f32) f32.const -1.5))''')
        for targets in ((0,), (1,), (2, 3, 4), (0, 1, 2, 3, 4)):
            self.agree(source, ['15', '6.25000000', '-1.50000000'], targets, seeds=(42,))

    def test_indirect_float_calls_and_type_mismatch(self):
        source = self.compile('''(module (type $t (func (param f32 f64) (result f64)))
          (table 2 funcref) (elem (i32.const 0) $good $bad)
          (func $good (type $t) local.get 0 f64.promote_f32 local.get 1 f64.add)
          (func $bad (param i32 i64) (result i64) local.get 1)
          (func (export "run") (result f64) f32.const 1.5 f64.const 2.25 i32.const 0 call_indirect (type $t))
          (func (export "bad") (result f64) f32.const 1.5 f64.const 2.25 i32.const 1 call_indirect (type $t)))''')
        for targets in ((2, 3), (0, 2, 3)):
            self.agree(source, ['3.75000000'], targets, export='run', seeds=(42,))
            result = self.command(ENGINE, '--run-export', 'bad', self.protect(source, targets))
            self.assertNotEqual(result.returncode, 0); self.assertIn('indirect call type mismatch', result.stderr)

    def test_native_imports_float_parameters(self):
        # A single import avoids WABT rewriting multiple imports to compact-import encoding.
        # Rewriting ordinary sections after protection invalidates the association checksum.
        for name, params, args in (('print_i32_f32', 'i32 f32', 'i32.const 7 f32.const 1.5'),
                                   ('print_f64_f64', 'f64 f64', 'f64.const 2.25 f64.const 3.75')):
            source = self.compile(f'''(module (import "spectest" "{name}" (func $print (param {params})))
              (func (export "run") (result f64) {args} call $print f64.const 3.75))''')
            for fusion in ('off', 'on'):
                output = self.protect(source, (1,), fusion)
                encoded = ''.join('\\' + format(byte, '02x') for byte in output.read_bytes())
                script = self.root / f'host-{name}-{fusion}.wast'
                script.write_text(f'(module binary "{encoded}")\n(assert_return (invoke "run") (f64.const 3.75))\n')
                result = self.command(ENGINE, script)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(': OK', result.stdout)

    def test_imported_defined_functions_return_float_values(self):
        host = self.compile('''(module (func (export "add") (param f32 f64) (result f64)
          local.get 0 f64.promote_f32 local.get 1 f64.add))''')
        caller = self.compile('''(module (import "host" "add" (func $add (param f32 f64) (result f64)))
          (func (export "run") (result f64) f32.const 1.5 f64.const 2.25 call $add))''')
        for host_module in (host, self.protect(host)):
            protected = self.protect(caller, (1,))
            host_bytes = ''.join('\\' + format(byte, '02x') for byte in host_module.read_bytes())
            caller_bytes = ''.join('\\' + format(byte, '02x') for byte in protected.read_bytes())
            script = self.root / f'import-{next(self.ids)}.wast'
            script.write_text(f'(module $host binary "{host_bytes}")\n(register "host" $host)\n'
                              f'(module binary "{caller_bytes}")\n(assert_return (invoke "run") (f64.const 3.75))\n')
            result = self.command(ENGINE, script)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(': OK', result.stdout)

    def test_multiple_memories_and_float_bounds_traps(self):
        for width in (32, 64):
            source = self.compile(f'''(module (memory 1) (memory 1)
              (func (export "run") (result i{width})
                i32.const 1 f{width}.const -0 f{width}.store 1 offset=2 align=1
                i32.const 2 f{width}.load 1 offset=1 align=1 i{width}.reinterpret_f{width}))''', features=('--enable-multi-memory',))
            output = self.protect(source, features=('--enable-web-assembly3',))
            result = self.command(ENGINE, '--enable-web-assembly3', '--run-export', 'run', output)
            self.assertEqual((result.returncode, result.stdout.strip()), (0, str(-(1 << (width - 1)))), result.stderr)
            for op in ('load', 'store'):
                body = f'i32.const 65535 f{width}.load drop' if op == 'load' else f'i32.const 65535 f{width}.const 1 f{width}.store'
                source = self.compile(f'(module (memory 1) (func (export "run") {body}))')
                for module in (source, self.protect(source)):
                    result = self.command(ENGINE, '--run-export', 'run', module)
                    self.assertNotEqual(result.returncode, 0); self.assertIn('out of bounds memory access', result.stderr)

    def test_manifest_recovery_reproducibility_and_previous_formats(self):
        source = self.compile()
        g2_output, g3_output = self.protect(source, (3,), 'off'), self.protect(source, (3,))
        g2_program = recover(g2_output.read_bytes())['functions'][0]['canonical_program_sha256']
        self.assertEqual(g2_program, recover(g3_output.read_bytes())['functions'][0]['canonical_program_sha256'])
        self.assertEqual(self.values(g3_output), g1.EXPECTED)
        self.assertEqual(g3_output.read_bytes(), self.protect(source, (3,)).read_bytes())
        self.assertNotEqual(g3_output.read_bytes(), self.protect(source, (3,), seed=43).read_bytes())
        self.assertEqual(self.values(self.protect(source, (3,), 'off', mode='identity')), g1.EXPECTED)
        floating = self.compile('(module (func (param f32) (result f32) local.get 0 f32.const 0.5 f32.add))')
        output = self.root / 'manifest.wasm'
        result = self.command(sys.executable, RESEARCH / 'protect.py', '--engine', ENGINE, '--input', floating,
                              '--output', output, '--function', 0, '--mode', 'permuted', '--seed', 42,
                              '--fusion', 'on', '--floating-point')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(Path(str(output) + '.manifest.json').read_text())['protection']['format_version'], 5)
        for flags in ((), ('--protection-mode', 'identity'), ('--fusion', 'off'), ('--extended',)):
            result = self.command(ENGINE, *flags, '--protect-function', 0, '--output', self.root / 'old.wasm', floating)
            self.assertNotEqual(result.returncode, 0); self.assertFalse((self.root / 'old.wasm').exists())

    def test_malformed_signature_global_and_float_frame_operands(self):
        source = self.compile('''(module (global f64 (f64.const 2.25))
          (func (export "run") (param f32) (result f64) local.get 0 f64.promote_f32 global.get 0 f64.add))''')
        output = self.protect(source)
        items = g1.sections(output.read_bytes()); _, payload = g2.payload_location(items)
        loc = record(payload); mapping = struct.unpack_from(f"<{loc['mapping_count']}H", payload, loc['map'])
        cases = []
        def change(offset, fmt, value, message):
            mutated = bytearray(payload); struct.pack_into(fmt, mutated, offset, value); cases.append((mutated, message))
        change(56 + 40, '<B', 0x7f, 'parameter type mismatch')
        change(56 + 41, '<B', 0x7d, 'return type mismatch')
        for pc in range(loc['count']):
            offset = loc['stream'] + pc * 24
            fields = struct.unpack_from('<HHIIIQ', payload, offset); name = OPCODE_NAMES[mapping[fields[0]]]
            if name == 'F64PromoteF32': change(offset + 12, '<I', 4, 'frame access')
            if name == 'GlobalGet64':
                change(offset, '<H', mapping.index(OPCODE_NAMES.index('GlobalGet32')), 'global type mismatch')
        for changed, message in cases:
            bad = self.root / f'bad-{next(self.ids)}.wasm'; bad.write_bytes(g2.replace_payload(items, changed))
            result = self.command(ENGINE, '--run-export', 'run', bad)
            self.assertNotEqual(result.returncode, 0); self.assertIn(message, result.stderr)

    def test_float_start_and_unsupported_types(self):
        source = self.compile('''(module (global $g (mut f64) (f64.const -0))
          (func $start f64.const 1.25 global.set $g) (start $start)
          (func (export "run") (result f64) global.get $g))''')
        self.agree(source, ['1.25000000'], (0, 1), seeds=(42,))
        unsupported = self.compile('(module (func (param v128) (result v128) local.get 0))')
        result = self.command(ENGINE, '--floating-point', '--protect-function', 0,
                              '--output', self.root / 'unsupported.wasm', unsupported)
        self.assertNotEqual(result.returncode, 0); self.assertFalse((self.root / 'unsupported.wasm').exists())

    def test_official_scalar_specification_suites(self):
        # Keep the upstream assertions unchanged; replace only valid top-level module bodies.
        for name in ('f32', 'f64', 'conversions', 'float_memory', 'float_misc', 'float_exprs'):
            with self.subTest(suite=name):
                original = SPEC / f'{name}.wast'
                source = original.read_text(); lines = source.splitlines(keepends=True)
                json_path = self.root / f'{name}.json'
                result = self.command('wast2json', original, '-o', json_path)
                self.assertEqual(result.returncode, 0, result.stderr)
                modules = [item for item in json.loads(json_path.read_text())['commands'] if item['type'] == 'module']
                for fusion in ('off', 'on'):
                    replacements = []
                    for item in modules:
                        module = self.root / item['filename']
                        function_section = next((data for kind, data in g1.sections(module.read_bytes()) if kind == 3), b'\0')
                        count = g1.read_uleb(function_section, 0)[0]
                        if not count: continue
                        output = self.protect(module, tuple(range(count)), fusion)
                        start = source.index('(module', sum(map(len, lines[:item['line'] - 1])))
                        end = expression_end(source, start)
                        label = item.get('name', '')
                        encoded = ''.join('\\' + format(byte, '02x') for byte in output.read_bytes())
                        replacements.append((start, end, f'(module {label} binary "{encoded}")'))
                    protected = source
                    for start, end, replacement in reversed(replacements):
                        protected = protected[:start] + replacement + protected[end:]
                    script = self.root / f'{name}-{fusion}.wast'; script.write_text(protected)
                    result = self.command(ENGINE, script)
                    self.assertEqual(result.returncode, 0, result.stderr[-3000:])
                    self.assertNotIn(': FAIL', result.stdout)

    def test_float_pilot_measurement_and_profile_tools(self):
        source = self.compile(Path(__file__).with_name('float-pilot.wat').read_text())
        output = self.protect(source, (0, 1))
        self.assertEqual(self.values(source), ['500.00000000', '500.00000000', '5000000.00000000', '5000000.00000000'])
        self.assertEqual(self.values(output, 'float32_1000'), ['500.00000000'])
        self.assertEqual(self.values(output, 'float64_1000'), ['500.00000000'])
        directory = self.root / 'measure'
        result = self.command(sys.executable, RESEARCH / 'measure.py', '--engine', ENGINE, '--wasm', output,
                              '--group', 'G3', '--export', 'float32_1000', '--expected', '500.00000000',
                              '--runs', 2, '--warmups', 1, '--out-dir', directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        meta = json.loads((directory / 'metadata.json').read_text())
        self.assertEqual((meta['protection']['format_version'], meta['correctness_exports']), (5, ['float32_1000']))
        result = self.command(sys.executable, RESEARCH / 'measure.py', '--engine', ENGINE, '--wasm', output,
                              '--group', 'G3', '--export', 'float32_1000', '--expected', '0',
                              '--runs', 1, '--warmups', 0, '--out-dir', self.root / 'wrong-result')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'wrong-result/summary.json').exists())
        result = self.command(sys.executable, RESEARCH / 'profile_protected.py', '--engine', ENGINE, '--wasm', output,
                              '--export', 'float32_1000', '--expected', '500.00000000', '--output', self.root / 'profile.json')
        self.assertEqual(result.returncode, 0, result.stderr)
        profile = json.loads((self.root / 'profile.json').read_text())
        self.assertEqual(profile['totals']['semantic_instruction_count'],
                         profile['totals']['dispatch_count'] + profile['totals']['fused_dispatch_count'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True, type=Path)
    args, remaining = parser.parse_known_args()
    ENGINE = args.engine.resolve(strict=True)
    g1.ENGINE = g2.ENGINE = ENGINE
    unittest.main(argv=[__file__, *remaining], verbosity=2)
