#!/usr/bin/env python3
"""Measure matched artifacts in shuffled G0--G4 rounds, one new process per run."""
import argparse
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess

from comparison_support import load_artifact_manifest, sha256
from measure import cpu_model, run_export


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, type=Path, help="build_comparison.py's comparison.json")
    parser.add_argument("--engine", type=Path, help="default: the suite's validated engine")
    parser.add_argument("--export", dest="export_name", default="bench_1m")
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--schedule-seed", type=int, default=2026)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0 or args.timeout <= 0:
        parser.error("runs >= 1, warmups >= 0 and timeout > 0 are required")
    out = None
    try:
        suite_path = args.suite.resolve(strict=True)
        suite = json.loads(suite_path.read_text())
        if not isinstance(suite, dict) or suite.get("schema") != "walrus.comparison-suite.v1":
            raise ValueError("invalid comparison suite")
        engine = (args.engine or Path(suite["engine"]["path"])).resolve(strict=True)
        if not engine.is_file() or not os.access(engine, os.X_OK):
            raise ValueError("engine must be executable")
        batches, names = [], set()
        for entry in suite["benchmarks"]:
            name = entry["benchmark"]
            if name in names:
                raise ValueError("duplicate benchmark in suite")
            names.add(name)
            groups = entry["artifacts"]
            if not {"G0", "G1", "G2", "G3"} <= set(groups) or set(groups) - {"G0", "G1", "G2", "G3", "G4"}:
                raise ValueError("suite requires G0--G3, with optional G4")
            prepared = {}
            baseline_hash = sha256(suite_path.parent / groups["G0"]["wasm"])
            for group in sorted(groups):
                wasm = (suite_path.parent / groups[group]["wasm"]).resolve(strict=True)
                manifest_path = (suite_path.parent / groups[group]["manifest"]).resolve(strict=True)
                manifest = load_artifact_manifest(manifest_path, wasm, group)
                if (manifest.get("comparison_id") != entry["comparison_id"] or
                    manifest.get("benchmark") != name or manifest.get("baseline_sha256") != baseline_hash):
                    raise ValueError("artifacts do not share the suite's benchmark and baseline")
                if args.export_name not in manifest["expected"]:
                    raise ValueError("export is not covered by the artifact manifest")
                prepared[group] = {"wasm": wasm, "manifest_path": manifest_path, "manifest": manifest}
            if any(item["manifest"]["expected"] != prepared["G0"]["manifest"]["expected"] for item in prepared.values()):
                raise ValueError("comparison groups have different expected results")
            batches.append((entry, prepared))
        if not batches:
            raise ValueError("comparison suite has no benchmarks")
        # Complete provenance checks before creating the result directory.
        candidate = args.out_dir.resolve()
        candidate.mkdir(parents=True, exist_ok=False)
        out = candidate
        environment = {"engine": str(engine), "engine_sha256": sha256(engine), "engine_bytes": engine.stat().st_size,
                       "suite": str(suite_path), "suite_sha256": sha256(suite_path), "measurement": "end_to_end_process",
                       "started_at_utc": datetime.now(timezone.utc).isoformat(), "clock": "perf_counter_ns",
                       "platform": platform.platform(), "machine": platform.machine(), "cpu_model": cpu_model(),
                       "python": platform.python_version(), "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
                       "load_average_before": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
                       "export": args.export_name, "runs": args.runs, "warmups": args.warmups,
                       "warmup_scope": "separate processes; does not reuse an instance", "schedule_seed": args.schedule_seed,
                       "G4_present_in_all_benchmarks": all("G4" in group for _, group in batches)}
        (out / "metadata.json").write_text(json.dumps(environment, indent=2) + "\n")
        rng, rows = random.Random(args.schedule_seed), []
        for entry, groups in batches:
            name = entry["benchmark"]
            root = out / name
            root.mkdir()
            times = {group: [] for group in groups}
            for group, item in groups.items():
                group_dir = root / group.lower()
                group_dir.mkdir()
                details = {**environment, "group": group, "benchmark": name, "comparison_id": entry["comparison_id"],
                           "wasm": str(item["wasm"]), "wasm_sha256": sha256(item["wasm"]), "wasm_bytes": item["wasm"].stat().st_size,
                           "expected": item["manifest"]["expected"][args.export_name], "expected_source": "artifact_manifest",
                           "artifact_manifest": {"path": str(item["manifest_path"]), "sha256": sha256(item["manifest_path"]), "data": item["manifest"]},
                           "command": [str(engine), "--run-export", args.export_name, str(item["wasm"])]}
                (group_dir / "metadata.json").write_text(json.dumps(details, indent=2) + "\n")
                checks = {}
                for export, expected in item["manifest"]["expected"].items():
                    _, checks[export] = run_export(engine, item["wasm"], export, args.timeout, expected)
                (group_dir / "correctness.json").write_text(json.dumps(checks, indent=2) + "\n")
            schedule = []
            for phase, count in (("warmup", args.warmups), ("measurement", args.runs)):
                for round_number in range(1, count + 1):
                    order = list(groups)
                    rng.shuffle(order)
                    schedule.append({"phase": phase, "round": round_number, "order": order})
            (root / "schedule.json").write_text(json.dumps(schedule, indent=2) + "\n")
            with (root / "raw.csv").open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["group", "measurement", "round", "order_in_round", "export", "elapsed_ns", "elapsed_ms", "result"])
                for round_spec in schedule:
                    for position, group in enumerate(round_spec["order"], 1):
                        item = groups[group]
                        ns, actual = run_export(engine, item["wasm"], args.export_name, args.timeout,
                                                item["manifest"]["expected"][args.export_name])
                        if round_spec["phase"] == "measurement":
                            times[group].append(ns / 1_000_000)
                            writer.writerow([group, "end_to_end_process", round_spec["round"], position,
                                             args.export_name, ns, ns / 1_000_000, actual])
                            stream.flush()
                    print(f"{name}: {round_spec['phase']} {round_spec['round']} complete", flush=True)
            for group, values in times.items():
                summary = {"group": group, "measurement": "end_to_end_process", "benchmark": name, "export": args.export_name,
                           "runs": len(values), "median_ms": statistics.median(values), "mean_ms": statistics.mean(values),
                           "stdev_ms": statistics.stdev(values) if len(values) > 1 else None,
                           "min_ms": min(values), "max_ms": max(values)}
                (root / group.lower() / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
                size = groups[group]["wasm"].stat().st_size
                baseline_size = groups["G0"]["wasm"].stat().st_size
                rows.append({**summary, "wasm_bytes": size, "size_ratio_vs_g0": size / baseline_size,
                             "slowdown_vs_g0": summary["median_ms"] / statistics.median(times["G0"])})
        with (out / "comparison.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        (out / "comparison.json").write_text(json.dumps({"metadata": environment, "results": rows}, indent=2) + "\n")
        print(f"Results: {out / 'comparison.csv'}")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.TimeoutExpired) as error:
        if out is not None:
            (out / "error.json").write_text(json.dumps({"error": str(error)}, indent=2) + "\n")
        parser.exit(1, f"Comparison measurement stopped: {error}\n")


if __name__ == "__main__":
    main()
