#!/usr/bin/env python3
"""G0/G1 pilot: check outputs and measure end-to-end Walrus process latency.

Every observation starts a NEW process and includes startup, module loading,
instantiation, the selected exported function, output capture, and shutdown.
This script does not measure kernel-only execution time.
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import time


EXPECTED = {
    "calc_20": "23",
    "calc_5": "3",
    "sum_1000": "500500",
    "sum_1m": "500000500000",
    "sum_10m": "50000005000000",
}


def protection_metadata(wasm):
    """Read experiment metadata; runtime validation remains Walrus's job."""
    data = wasm.read_bytes()
    if data[:8] != b"\x00asm\x01\x00\x00\x00":
        raise ValueError("expected a core Wasm module")

    def read_uleb(offset, limit):
        value = 0
        for i in range(5):
            if offset >= limit:
                raise ValueError("truncated Wasm section")
            byte = data[offset]
            offset += 1
            if i == 4 and byte & 0xf0:
                raise ValueError("invalid section length")
            value |= (byte & 127) << (7 * i)
            if not byte & 128:
                return value, offset
        raise ValueError("invalid section length")

    payload = None
    offset = 8
    while offset < len(data):
        kind = data[offset]
        size, begin = read_uleb(offset + 1, len(data))
        end = begin + size
        if end > len(data):
            raise ValueError("truncated Wasm section")
        if kind == 0:
            name_size, name = read_uleb(begin, end)
            if name + name_size > end:
                raise ValueError("truncated section name")
            if data[name:name + name_size] == b"walrus.protected.g1":
                if payload is not None:
                    raise ValueError("duplicate G1 section")
                payload = data[name + name_size:end]
        offset = end
    if payload is None:
        return None
    if len(payload) < 24 or payload[:4] != b"WGP1":
        raise ValueError("invalid G1 header")
    version, abi, checksum, count = struct.unpack_from("<IIQI", payload, 4)
    offset = 24
    functions = []
    for _ in range(count):
        if offset + 24 > len(payload):
            raise ValueError("truncated G1 function record")
        index, frame, params, results, instructions, mapping = struct.unpack_from("<6I", payload, offset)
        offset += 24 + params + results + 2 * mapping + 24 * instructions
        if offset > len(payload):
            raise ValueError("truncated G1 instruction stream")
        functions.append({"index": index, "frame_bytes": frame, "instruction_count": instructions})
    if offset != len(payload):
        raise ValueError("trailing G1 payload bytes")
    return {"format_version": version, "abi_word_bytes": abi,
            "skeleton_checksum": f"{checksum:016x}", "functions": functions}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_export(engine, wasm, export, timeout):
    command = [str(engine), "--run-export", export, str(wasm)]
    start = time.perf_counter_ns()
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout
    )
    elapsed_ns = time.perf_counter_ns() - start
    actual = completed.stdout.strip()
    if completed.returncode != 0 or actual != EXPECTED[export]:
        raise RuntimeError(
            f"{export}: expected {EXPECTED[export]!r}, got {actual!r}; "
            f"exit={completed.returncode}; stderr={completed.stderr.strip()!r}"
        )
    return elapsed_ns, actual


def cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", required=True, choices=("G0", "G1"))
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--wasm", required=True, type=Path)
    parser.add_argument("--export", dest="export_name", choices=EXPECTED, default="sum_10m")
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--out-dir", type=Path)
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0 or args.timeout <= 0:
        parser.error("runs >= 1, warmups >= 0, timeout > 0 are required")
    engine = args.engine.resolve(strict=True)
    wasm = args.wasm.resolve(strict=True)
    if not engine.is_file() or not os.access(engine, os.X_OK) or not wasm.is_file():
        parser.error("engine must be executable and wasm must be a file")
    try:
        protection = protection_metadata(wasm)
    except ValueError as error:
        parser.error(str(error))
    if (args.group == "G1") != (protection is not None):
        parser.error("--group must match whether the module contains a G1 protection section")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out_dir = args.out_dir or Path("artifacts") / f"{args.group}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=False)
    metadata = {
        "group": args.group,
        "measurement": "end_to_end_process",
        "clock": "perf_counter_ns",
        "started_at_utc": stamp,
        "engine": str(engine),
        "engine_sha256": sha256(engine),
        "engine_bytes": engine.stat().st_size,
        "wasm": str(wasm),
        "wasm_sha256": sha256(wasm),
        "wasm_bytes": wasm.stat().st_size,
        "protection": protection,
        "export": args.export_name,
        "expected": EXPECTED[args.export_name],
        "runs": args.runs,
        "warmups": args.warmups,
        "warmup_scope": "separate processes; does not reuse an instance",
        "command": [str(engine), "--run-export", args.export_name, str(wasm)],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": cpu_model(),
        "python": platform.python_version(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "load_average_before": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    try:
        correctness = {}
        for export in EXPECTED:
            _, value = run_export(engine, wasm, export, args.timeout)
            correctness[export] = value
            print(f"PASS {export} -> {value}", flush=True)
        (out_dir / "correctness.json").write_text(json.dumps(correctness, indent=2) + "\n")

        for _ in range(args.warmups):
            run_export(engine, wasm, args.export_name, args.timeout)

        timings_ms = []
        with (out_dir / "raw.csv").open("w", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(["group", "measurement", "run", "export", "elapsed_ns", "elapsed_ms", "result"])
            for run in range(1, args.runs + 1):
                elapsed_ns, result = run_export(engine, wasm, args.export_name, args.timeout)
                elapsed_ms = elapsed_ns / 1_000_000
                timings_ms.append(elapsed_ms)
                writer.writerow([args.group, "end_to_end_process", run, args.export_name, elapsed_ns, elapsed_ms, result])
                output.flush()

        summary = {
            "group": args.group,
            "measurement": "end_to_end_process",
            "export": args.export_name,
            "runs": args.runs,
            "median_ms": statistics.median(timings_ms),
            "mean_ms": statistics.mean(timings_ms),
            "stdev_ms": statistics.stdev(timings_ms) if args.runs > 1 else None,
            "min_ms": min(timings_ms),
            "max_ms": max(timings_ms),
        }
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
        print(f"Saved: {out_dir.resolve()}")
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
        (out_dir / "error.json").write_text(json.dumps({"error": str(error)}, indent=2) + "\n")
        raise SystemExit(f"Measurement stopped: {error}\nLogs: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
