#!/usr/bin/env python3
"""Comparison provenance, reactor initialization and process-timer integration."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

RESEARCH = Path(__file__).resolve().parents[2] / "tools/research"
sys.path.insert(0, str(RESEARCH))
from comparison_support import (HEADER, SCHEMA, function_exports, initialize_reactor,
                                load_artifact_manifest, sections, sha256)
from build_comparison import COMPILE_FLAGS

ENGINE = None
EMCC = None
TIGRESS = None


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="walrus-comparison-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ids = 0

    def command(self, *args):
        return subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=180)

    def compile(self, text):
        self.ids += 1
        wat, wasm = self.root / f"f{self.ids}.wat", self.root / f"f{self.ids}.wasm"
        wat.write_text(text)
        result = self.command("wat2wasm", wat, "-o", wasm)
        self.assertEqual(result.returncode, 0, result.stderr)
        return wasm

    def reactor(self):
        raw = self.compile('''(module
          (global $g (mut i32) (i32.const 0))
          (func $init (export "_initialize") i32.const 7 global.set $g)
          (func $k (export "kernel") (param i32) (result i32)
            local.get 0 global.get $g i32.add)
          (func (export "bench_one") (result i32) i32.const 1 call $k))''')
        wasm = self.root / "reactor.wasm"
        data, _ = initialize_reactor(raw.read_bytes())
        wasm.write_bytes(data)
        return raw, wasm

    def manifest(self, wasm, group="G0"):
        # G4 fixtures test only label/provenance validation. They are NOT Tigress artifacts.
        path = self.root / f"{wasm.name}.{group}.json"
        data = {"schema": SCHEMA, "group": group, "comparison_id": "test-fixture",
                "benchmark": "fixture", "baseline_sha256": sha256(wasm),
                "artifact": {"sha256": sha256(wasm), "bytes": wasm.stat().st_size},
                "expected": {"bench_one": "8"}, "tigress": None}
        if group == "G4":
            data["tigress"] = {"version": "unit-test fixture; NOT a Tigress build", "command": ["fixture"]}
        path.write_text(json.dumps(data))
        return path

    def measure(self, wasm, group="G0", manifest=None, **options):
        command = [sys.executable, RESEARCH / "measure.py", "--engine", ENGINE, "--wasm", wasm,
                   "--group", group, "--export", "bench_one", "--runs", "2", "--warmups", "1",
                   "--out-dir", self.root / "result"]
        if manifest:
            command += ["--artifact-manifest", manifest]
        for name, value in options.items():
            command += ["--" + name.replace("_", "-"), value]
        return self.command(*command)

    def test_initializer_runs_during_instantiation(self):
        raw, wasm = self.reactor()
        self.assertEqual(self.command(ENGINE, "--run-export", "bench_one", raw).stdout.strip(), "1")
        result = self.command("wasm-validate", wasm)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.command(ENGINE, "--run-export", "bench_one", wasm).stdout.strip(), "8")
        self.assertEqual(function_exports(wasm.read_bytes())["kernel"], 1)

    def test_shared_constructor_runs_main_once_before_export(self):
        if EMCC is None:
            self.skipTest("--emcc is required for the constructor regression")
        source = self.root / "init.c"
        source.write_text('''static unsigned calls;
          int main(int argc, char **argv, char **envp) {
            calls += (argc == 0 && argv == 0 && envp == 0) ? 1u : 100u;
            return 0;
          }
          unsigned bench_one(void) { return calls; }''')
        raw, wasm = self.root / "raw.wasm", self.root / "initialized.wasm"
        result = self.command(EMCC, "-O2", *COMPILE_FLAGS,
                              '-sEXPORTED_FUNCTIONS=["_bench_one"]', source,
                              RESEARCH / "benchmarks/startup.c", "-o", raw)
        self.assertEqual(result.returncode, 0, result.stderr)
        wasm.write_bytes(initialize_reactor(raw.read_bytes())[0])
        self.assertEqual(self.command(ENGINE, "--run-export", "bench_one", raw).stdout.strip(), "0")
        result = self.command(ENGINE, "--run-export", "bench_one", wasm)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "1")

    def test_initializer_patching_rejects_imports(self):
        wasm = self.compile('(module (import "env" "f" (func)) (func (export "_initialize")))')
        with self.assertRaisesRegex(ValueError, "no imports"):
            initialize_reactor(wasm.read_bytes())

    def test_initializer_patching_rejects_wrong_signature(self):
        wasm = self.compile('(module (func (export "_initialize") (result i32) i32.const 0))')
        with self.assertRaisesRegex(ValueError, "type"):
            initialize_reactor(wasm.read_bytes())

    def test_initializer_patching_rejects_existing_start(self):
        _, wasm = self.reactor()
        with self.assertRaisesRegex(ValueError, "pre-existing"):
            initialize_reactor(wasm.read_bytes())

    def test_missing_initializer_and_truncation_are_rejected(self):
        wasm = self.compile('(module (func (export "kernel")))')
        with self.assertRaisesRegex(ValueError, "missing"):
            initialize_reactor(wasm.read_bytes())
        with self.assertRaises(ValueError):
            sections(HEADER + b"\x07\x80")

    def test_manifest_output_checks_are_used_by_timer(self):
        _, wasm = self.reactor()
        result = self.measure(wasm, manifest=self.manifest(wasm))
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads((self.root / "result/summary.json").read_text())
        meta = json.loads((self.root / "result/metadata.json").read_text())
        self.assertEqual(summary["runs"], 2)
        self.assertEqual(meta["expected_source"], "artifact_manifest")
        self.assertEqual(meta["measurement"], "end_to_end_process")

    def test_g4_requires_provenance(self):
        _, wasm = self.reactor()
        result = self.measure(wasm, group="G4", expected="8")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --artifact-manifest", result.stderr)
        self.assertFalse((self.root / "result").exists())

    def test_g4_manifest_requires_tigress_record(self):
        _, wasm = self.reactor()
        path = self.manifest(wasm, "G4")
        data = json.loads(path.read_text())
        data["tigress"] = None
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Tigress provenance"):
            load_artifact_manifest(path, wasm, "G4")

    def test_manifest_rejects_changed_wasm_and_wrong_group(self):
        _, wasm = self.reactor()
        path = self.manifest(wasm)
        with self.assertRaisesRegex(ValueError, "group"):
            load_artifact_manifest(path, wasm, "G4")
        wasm.write_bytes(wasm.read_bytes() + b"\x00\x01\x00")
        result = self.measure(wasm, manifest=path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Wasm bytes", result.stderr)
        self.assertFalse((self.root / "result").exists())

    def test_explicit_wrong_expected_is_rejected(self):
        _, wasm = self.reactor()
        result = self.measure(wasm, manifest=self.manifest(wasm), expected="9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disagrees", result.stderr)
        self.assertFalse((self.root / "result").exists())

    def protected_suite(self):
        _, wasm = self.reactor()
        baseline = sha256(wasm)
        artifacts = {"G0": {"wasm": wasm.name, "manifest": self.manifest(wasm).name}}
        for group, mode, fusion in (("G1", "identity", "off"), ("G2", "permuted", "off"), ("G3", "permuted", "on")):
            protected = self.root / f"{group}.wasm"
            command = [ENGINE, "--floating-point", "--protection-mode", mode, "--fusion", fusion,
                       "--protect-function", "1", "--output", protected, wasm]
            if mode == "permuted":
                command += ["--seed", "42"]
            result = self.command(*command)
            self.assertEqual(result.returncode, 0, result.stderr)
            path = self.manifest(protected, group)
            data = json.loads(path.read_text())
            data["baseline_sha256"] = baseline
            path.write_text(json.dumps(data))
            artifacts[group] = {"wasm": protected.name, "manifest": path.name}
        suite = {"schema": "walrus.comparison-suite.v1", "engine": {"path": ENGINE}, "benchmarks": [
            {"benchmark": "fixture", "comparison_id": "test-fixture", "artifacts": artifacts}]}
        path = self.root / "suite.json"
        path.write_text(json.dumps(suite))
        return path, artifacts

    def test_g4_rejects_walrus_protected_module(self):
        _, artifacts = self.protected_suite()
        wasm = self.root / artifacts["G3"]["wasm"]
        with self.assertRaisesRegex(ValueError, "no Walrus protection"):
            load_artifact_manifest(self.manifest(wasm, "G4"), wasm, "G4")

    def test_interleaved_rounds_and_no_overwrite(self):
        path, _ = self.protected_suite()
        output = self.root / "suite-result"
        command = [sys.executable, RESEARCH / "measure_comparison.py", "--suite", path, "--export", "bench_one",
                   "--runs", "2", "--warmups", "1", "--out-dir", output]
        result = self.command(*command)
        self.assertEqual(result.returncode, 0, result.stderr)
        schedule = json.loads((output / "fixture/schedule.json").read_text())
        self.assertEqual(len(schedule), 3)
        for entry in schedule:
            self.assertEqual(sorted(entry["order"]), ["G0", "G1", "G2", "G3"])
        for group in ("g0", "g1", "g2", "g3"):
            summary = json.loads((output / "fixture" / group / "summary.json").read_text())
            self.assertEqual(summary["runs"], 2)
        checksum = sha256(output / "comparison.json")
        result = self.command(*command)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sha256(output / "comparison.json"), checksum)
        self.assertFalse((output / "error.json").exists())

    def test_suite_rejects_mismatched_baselines(self):
        path, artifacts = self.protected_suite()
        manifest = self.root / artifacts["G2"]["manifest"]
        data = json.loads(manifest.read_text())
        data["baseline_sha256"] = "wrong"
        manifest.write_text(json.dumps(data))
        result = self.command(sys.executable, RESEARCH / "measure_comparison.py", "--suite", path,
                              "--export", "bench_one", "--out-dir", self.root / "suite-result")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("baseline", result.stderr)
        self.assertFalse((self.root / "suite-result").exists())

    def test_real_c_build_and_existing_directory_preserved(self):
        if EMCC is None:
            self.skipTest("--emcc is required for the real C -> Wasm build test")
        output = self.root / "built"
        command = [sys.executable, RESEARCH / "build_comparison.py", "--engine", ENGINE, "--emcc", EMCC,
                   "--without-g4", "--benchmark", "sum_i64", "--out-dir", output]
        result = self.command(*command)
        self.assertEqual(result.returncode, 0, result.stderr)
        suite = json.loads((output / "comparison.json").read_text())
        self.assertEqual(suite["benchmarks"][0]["G4_status"], "not_generated: --without-g4")
        for group, entry in suite["benchmarks"][0]["artifacts"].items():
            manifest = load_artifact_manifest(output / entry["manifest"], output / entry["wasm"], group)
            self.assertEqual(manifest["correctness"], manifest["expected"])
            self.assertEqual(manifest["protection"]["format_version"] if group != "G0" else None,
                             5 if group != "G0" else None)
        checksum = sha256(output / "comparison.json")
        result = self.command(*command)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sha256(output / "comparison.json"), checksum)
        self.assertFalse((output / "error.json").exists())

    def test_real_tigress_build_and_g4_measurement(self):
        if EMCC is None or TIGRESS is None:
            self.skipTest("--emcc and --tigress are required for the real Tigress integration")
        output = self.root / "tigress-build"
        result = self.command(sys.executable, RESEARCH / "build_comparison.py", "--engine", ENGINE,
                              "--emcc", EMCC, "--tigress", TIGRESS, "--benchmark", "sum_i64",
                              "--seed", "42", "--out-dir", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        suite = json.loads((output / "comparison.json").read_text())
        benchmark = suite["benchmarks"][0]
        self.assertEqual(benchmark["G4_status"], "correctness_passed")
        artifact = benchmark["artifacts"]["G4"]
        wasm, manifest = output / artifact["wasm"], output / artifact["manifest"]
        data = load_artifact_manifest(manifest, wasm, "G4")
        self.assertEqual(data["correctness"], data["expected"])
        self.assertIn("main(0, NULL, NULL)", data["initialization"])
        g0 = json.loads((output / benchmark["artifacts"]["G0"]["manifest"]).read_text())
        self.assertNotEqual(data["compiled_functions"]["kernel"]["body_sha256"],
                            g0["compiled_functions"]["kernel"]["body_sha256"])
        result = self.measure(wasm, group="G4", manifest=manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads((self.root / "result/summary.json").read_text())
        self.assertEqual(summary["group"], "G4")
        self.assertEqual(summary["runs"], 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--emcc", type=Path)
    parser.add_argument("--tigress", type=Path)
    args = parser.parse_args()
    ENGINE = str(args.engine.resolve(strict=True))
    EMCC = str(args.emcc.resolve(strict=True)) if args.emcc else None
    TIGRESS = str(args.tigress.resolve(strict=True)) if args.tigress else None
    unittest.main(argv=[sys.argv[0]], verbosity=2)
