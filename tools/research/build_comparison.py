#!/usr/bin/env python3
"""Build a local, matched C -> Wasm G0--G4 pilot without changing Walrus."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

from comparison_support import (BENCHMARKS, INPUTS, SCHEMA, expected_outputs,
                                function_body, function_exports, initialize_reactor, sha256)
from protected_format import metadata, read_protection

ROOT = Path(__file__).resolve().parent
COMPILE_FLAGS = ["-std=c99", "-fno-vectorize", "-fno-slp-vectorize", "-fno-unroll-loops",
                 "-fno-fast-math", "-mno-simd128", "-mno-tail-call", "-mno-bulk-memory",
                 "--no-entry", "-sSTANDALONE_WASM=1", "-sFILESYSTEM=0", "-sASSERTIONS=0",
                 "-sSTACK_OVERFLOW_CHECK=0", "-sSTACK_SIZE=1048576", "-sINITIAL_MEMORY=16777216"]
TIGRESS_OPTIONS = ["--Transform=Virtualize", "--VirtualizeDispatch=switch",
                   "--VirtualizeOperands=registers", "--VirtualizeRandomOps=true",
                   "--VirtualizeRandomizeOperandOrder=false", "--VirtualizeSuperOpsRatio=0.0",
                   "--VirtualizeMaxMergeLength=0"]


def executable(value):
    found = shutil.which(str(value))
    if not found:
        raise ValueError(f"executable not found: {value}")
    path = Path(found).absolute()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"not executable: {path}")
    return path


def probe(value, flag, env=None):
    path = executable(value)
    result = subprocess.run([str(path), flag], capture_output=True, text=True, timeout=30, env=env)
    version = (result.stdout + result.stderr).strip()
    if result.returncode or not version:
        raise ValueError(f"version check failed: {path}\n{version}")
    return {"path": str(path), "sha256": sha256(path), "version": version}


class Commands:
    def __init__(self, root, timeout, env=None):
        self.root, self.timeout, self.records, self.env = root, timeout, [], env
        (root / "records").mkdir()

    def run(self, label, command):
        command = [str(part) for part in command]
        record = {"label": label, "command": command}
        self.records.append(record)
        (self.root / "records/commands.json").write_text(json.dumps(self.records, indent=2) + "\n")
        print(f"[{label}]", flush=True)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout, env=self.env)
        except subprocess.TimeoutExpired:
            record["status"] = "timeout"
            (self.root / "records/commands.json").write_text(json.dumps(self.records, indent=2) + "\n")
            raise
        (self.root / "records" / f"{label}.stdout.log").write_text(result.stdout)
        (self.root / "records" / f"{label}.stderr.log").write_text(result.stderr)
        record["returncode"] = result.returncode
        (self.root / "records/commands.json").write_text(json.dumps(self.records, indent=2) + "\n")
        if result.returncode:
            raise ValueError(f"{label} failed ({result.returncode}): {result.stderr.strip()}")
        return result.stdout


def disassemble(commands, tool, wasm, exports, label):
    output = commands.run(label, [tool, "-d", wasm])
    wasm.with_suffix(".disassembly.txt").write_text(output)
    stats = {}
    for name in ("kernel", "helper"):
        if name not in exports:
            continue
        pattern = rf"(?m)^[^\n]*func\[{exports[name]}\][^\n]*:\n(.*?)(?=^[^\n]*func\[|\Z)"
        match = re.search(pattern, output, re.S)
        if not match:
            raise ValueError(f"cannot locate {name} in disassembly")
        body = match.group(1)
        stats[name] = {"loop_count": len(re.findall(r"\|\s+loop\b", body)),
                       "body_sha256": hashlib.sha256(function_body(wasm.read_bytes(), exports[name])).hexdigest(),
                       "disassembly_sha256": hashlib.sha256(body.encode()).hexdigest()}
    if stats.get("kernel", {}).get("loop_count", 0) == 0:
        raise ValueError("kernel has no loop after compilation; do not measure an optimized-away workload")
    return stats


def build_one(args, tools, commands, benchmark, out):
    out.mkdir()
    source = out / "source"
    source.mkdir()
    for name in (f"{benchmark}.c", "comparison.h", "startup.c"):
        shutil.copyfile(ROOT / "benchmarks" / name, source / name)
    canonical = source / "canonical.c"
    commands.run(f"{benchmark}-preprocess", [tools["emcc"]["path"], "-std=c99", "-E", "-P",
                 source / f"{benchmark}.c", "-o", canonical])
    targets = ["kernel", "helper"] if benchmark == "call_mix" else ["kernel"]
    exports = [*INPUTS, *targets]
    flags = [f"-{args.optimization}", *COMPILE_FLAGS,
             "-sEXPORTED_FUNCTIONS=" + json.dumps(["_" + name for name in exports], separators=(",", ":"))]
    common = {"benchmark": benchmark, "source_sha256": sha256(canonical), "startup_source_sha256": sha256(source / "startup.c"), "compiler": tools["emcc"],
              "compile_flags": flags, "target_functions": targets,
              "initialization": "Wasm start -> _initialize -> shared constructor -> main(0, NULL, NULL)"}
    comparison_id = hashlib.sha256(json.dumps(common, sort_keys=True).encode()).hexdigest()
    expected = expected_outputs(benchmark)
    artifacts = {}

    def compile_module(group, c_source):
        raw = out / f"{group.lower()}.raw.wasm"
        commands.run(f"{benchmark}-{group}-compile", [tools["emcc"]["path"], *flags, c_source, source / "startup.c", "-o", raw])
        data, start_index = initialize_reactor(raw.read_bytes())
        wasm = out / f"{group.lower()}.wasm"
        wasm.write_bytes(data)
        commands.run(f"{benchmark}-{group}-validate", [tools["wasm_validate"]["path"], wasm])
        function_map = function_exports(data)
        if any(name not in function_map for name in exports):
            raise ValueError(f"{group} is missing required exports")
        stats = disassemble(commands, tools["wasm_objdump"]["path"], wasm, function_map,
                            f"{benchmark}-{group}-disassemble")
        return wasm, start_index, function_map, stats

    baseline, start, function_map, stats = compile_module("G0", canonical)
    indices = [function_map[name] for name in targets]

    def save(group, wasm, initializer, maps, stats=None, tigress=None):
        checks = {}
        for name, value in expected.items():
            actual = commands.run(f"{benchmark}-{group}-{name}", [tools["engine"]["path"], "--run-export", name, wasm]).strip()
            if actual != value:
                raise ValueError(f"{group} {name}: expected {value!r}, got {actual!r}")
            checks[name] = actual
        manifest = {"schema": SCHEMA, "group": group, "comparison_id": comparison_id, **common,
                    "artifact": {"file": wasm.name, "sha256": sha256(wasm), "bytes": wasm.stat().st_size},
                    "baseline_sha256": sha256(baseline), "target_function_indices": [maps[name] for name in targets],
                    "start_function_index": initializer, "expected": expected, "correctness": checks,
                    "engine": tools["engine"], "tigress": tigress, "compiled_functions": stats,
                    "protection": metadata(read_protection(wasm.read_bytes()))}
        manifest_path = Path(str(wasm) + ".manifest.json")
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        artifacts[group] = {"wasm": str(wasm.relative_to(commands.root)),
                            "manifest": str(manifest_path.relative_to(commands.root))}

    save("G0", baseline, start, function_map, stats)
    for group, mode, fusion in (("G1", "identity", "off"), ("G2", "permuted", "off"), ("G3", "permuted", "on")):
        wasm = out / f"{group.lower()}.wasm"
        command = [sys.executable, ROOT / "protect.py", "--engine", tools["engine"]["path"], "--input", baseline,
                   "--output", wasm, "--manifest", out / f"{group.lower()}.protection.json",
                   "--mode", mode, "--fusion", fusion, "--floating-point"]
        if mode == "permuted":
            command += ["--seed", args.seed]
        for index in indices:
            command += ["--function", index]
        commands.run(f"{benchmark}-{group}-protect", command)
        commands.run(f"{benchmark}-{group}-validate", [tools["wasm_validate"]["path"], wasm])
        save(group, wasm, start, function_map)

    if not args.without_g4:
        transformed = source / "tigress.c"
        command = [tools["tigress"]["path"], f"--Compiler={tools['emcc']['path']}",
                   f"--Environment={args.tigress_environment}", f"--Seed={args.seed}",
                   "--Verbosity=1", *TIGRESS_OPTIONS, "--Functions=" + ",".join(targets),
                   f"--out={transformed}", canonical]
        commands.run(f"{benchmark}-G4-virtualize", command)
        if not transformed.is_file() or sha256(transformed) == sha256(canonical):
            raise ValueError("Tigress did not generate transformed C")
        g4, g4_start, g4_map, g4_stats = compile_module("G4", transformed)
        if g4_stats["kernel"]["body_sha256"] == stats["kernel"]["body_sha256"]:
            raise ValueError("G4 kernel is unchanged after compilation")
        save("G4", g4, g4_start, g4_map, g4_stats, {**tools["tigress"], "command": [str(x) for x in command],
             "seed": args.seed, "environment": args.tigress_environment, "options": TIGRESS_OPTIONS,
             "transformed_source_sha256": sha256(transformed)})
    return {"benchmark": benchmark, "comparison_id": comparison_id, "artifacts": artifacts,
            "G4_status": "not_generated: --without-g4" if args.without_g4 else "correctness_passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--emcc", default="emcc")
    parser.add_argument("--tigress", default="tigress")
    parser.add_argument("--tigress-home", type=Path, help="distribution directory; defaults to TIGRESS_HOME or the executable's directory")
    parser.add_argument("--benchmark", choices=BENCHMARKS, action="append")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--optimization", choices=("O0", "O1", "O2", "O3"), default="O2")
    parser.add_argument("--tigress-environment", default="wasm:Linux:Emcc:4.6")
    parser.add_argument("--without-g4", action="store_true", help="explicitly build G0--G3 only; does not claim a G4 result")
    parser.add_argument("--check", action="store_true", help="check dependencies without generating artifacts")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    if not 1 <= args.seed <= 0x7fffffff:
        parser.error("use a seed in 1..2147483647 (Tigress seed 0 requests random generation)")
    if args.timeout <= 0 or not args.check and args.out_dir is None:
        parser.error("positive --timeout and --out-dir are required for a build")
    if args.benchmark and len(set(args.benchmark)) != len(args.benchmark):
        parser.error("duplicate benchmark")
    out = None
    try:
        tools = {"engine": {"path": str(executable(args.engine)), "sha256": sha256(executable(args.engine))},
                 "emcc": probe(args.emcc, "--version"), "wasm_validate": probe("wasm-validate", "--version"),
                 "wasm_objdump": probe("wasm-objdump", "--version")}
        child_env = os.environ.copy()
        if not args.without_g4:
            tigress_path = executable(args.tigress)
            home = args.tigress_home or (Path(child_env["TIGRESS_HOME"]) if child_env.get("TIGRESS_HOME") else None)
            if home is None and (tigress_path.parent / "machdeps_json").is_dir():
                home = tigress_path.parent
            if home is not None:
                home = home.resolve(strict=True)
                child_env["TIGRESS_HOME"] = str(home)
            tools["tigress"] = probe(tigress_path, "--Version", env=child_env)
            if home is not None:
                machine = {"amd64": "x86_64", "aarch64": "armv8", "arm64": "armv8"}.get(platform.machine(), platform.machine())
                native = home / f"{platform.system()}-{machine}"
                profile = "_".join(args.tigress_environment.split(":")[:3]) + "_0.json"
                files = [native / "cilly", native / "cilly.native", native / "envToFilename_exe.exe",
                         home / "machdeps_json" / profile]
                tools["tigress"].update({"home": str(home), "distribution_files": {
                    str(path.relative_to(home)): sha256(path) for path in files if path.is_file()}})
        if args.check:
            print(json.dumps({"tools": tools, "G4_enabled": not args.without_g4}, indent=2))
            return
        candidate = args.out_dir.resolve()
        candidate.mkdir(parents=True, exist_ok=False)
        out = candidate
        (out / "tools.json").write_text(json.dumps(tools, indent=2) + "\n")
        commands = Commands(out, args.timeout, child_env)
        benchmarks = [build_one(args, tools, commands, name, out / name)
                      for name in (args.benchmark or ["sum_i64"])]
        suite = {"schema": "walrus.comparison-suite.v1", "created_at_utc": datetime.now(timezone.utc).isoformat(),
                 "engine": tools["engine"], "seed": args.seed, "benchmarks": benchmarks,
                 "scope": "local correctness/measurement setup; not a protection-strength evaluation"}
        (out / "comparison.json").write_text(json.dumps(suite, indent=2) + "\n")
        print(f"Artifacts and build records: {out}")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        if out is not None and out.is_dir() and (out / "tools.json").exists():
            (out / "error.json").write_text(json.dumps({"error": str(error)}, indent=2) + "\n")
        parser.exit(1, f"Comparison build stopped: {error}\n")


if __name__ == "__main__":
    main()
