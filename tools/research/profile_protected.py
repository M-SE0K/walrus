#!/usr/bin/env python3
"""Collect protected dispatch counts in a separate instrumented pilot execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from measure import EXPECTED
from protected_format import metadata, read_protection

PREFIX = "WALRUS_PROTECTED_PROFILE "


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--wasm", required=True, type=Path)
    parser.add_argument("--export", dest="export_name", choices=EXPECTED, default="sum_1000")
    parser.add_argument("--output", required=True, type=Path, help="new JSON file")
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("output must be a new file")
        engine, wasm = args.engine.resolve(strict=True), args.wasm.resolve(strict=True)
        data = wasm.read_bytes()
        protection = read_protection(data)
        if protection is None:
            raise ValueError("expected a protected module")
        command = [str(engine), "--profile-protected", "--run-export", args.export_name, str(wasm)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if completed.returncode or completed.stdout.strip() != EXPECTED[args.export_name]:
            raise ValueError(f"execution failed or result mismatch: {completed.stderr.strip()}")
        calls = [json.loads(line[len(PREFIX):]) for line in completed.stderr.splitlines() if line.startswith(PREFIX)]
        if not calls:
            raise ValueError("no completed protected calls were profiled")
        for call in calls:
            if call["semantic_instruction_count"] != call["dispatch_count"] + call["fused_dispatch_count"]:
                raise ValueError("inconsistent profile counts")
        totals = {key: sum(call[key] for call in calls) for key in (
            "dispatch_count", "semantic_instruction_count", "fused_dispatch_count")}
        result = {
            "measurement": "instrumented_protected_dispatch_counts", "command": command,
            "engine_sha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
            "wasm_sha256": hashlib.sha256(data).hexdigest(), "export": args.export_name,
            "result": completed.stdout.strip(), "protection": metadata(protection),
            "calls": calls, "totals": totals,
        }
        with args.output.open("x") as output:
            output.write(json.dumps(result, indent=2) + "\n")
        print(json.dumps(totals, indent=2))
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Profiling stopped: {error}\n")


if __name__ == "__main__":
    main()
