#!/usr/bin/env python3
"""Generate a G1/G2/G3 artifact and a reproducibility manifest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from protected_format import metadata, read_protection


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, help="defaults to OUTPUT.manifest.json")
    parser.add_argument("--function", required=True, type=int, action="append")
    parser.add_argument("--mode", required=True, choices=("identity", "permuted"))
    parser.add_argument("--seed", type=int)
    parser.add_argument("--fusion", choices=("on", "off"), help="select format v3; on requires permuted mode")
    args = parser.parse_args()
    if args.fusion == "on" and args.mode != "permuted":
        parser.error("--fusion on requires permuted mode")
    if any(index < 0 or index > 0xffffffff for index in args.function):
        parser.error("function indices must be uint32")
    if len(set(args.function)) != len(args.function):
        parser.error("duplicate protection target")
    if (args.mode == "permuted") != (args.seed is not None):
        parser.error("--seed is required exactly in permuted mode")
    if args.seed is not None and not 0 <= args.seed <= 0xffffffffffffffff:
        parser.error("seed must be uint64")
    manifest_path = args.manifest or Path(str(args.output) + ".manifest.json")
    try:
        engine = args.engine.resolve(strict=True)
        source = args.input.resolve(strict=True)
        output = args.output.resolve()
        manifest_path = manifest_path.resolve()
        if not engine.is_file() or not os.access(engine, os.X_OK) or not source.is_file():
            raise ValueError("engine must be executable and input must be a file")
        if output == manifest_path or output.exists() or manifest_path.exists():
            raise ValueError("output and manifest must be distinct new files")
        if not output.parent.is_dir() or not manifest_path.parent.is_dir():
            raise ValueError("output and manifest directories must exist")
        input_sha, engine_sha = sha256(source), sha256(engine)
        command = [str(engine), "--protection-mode", args.mode]
        if args.seed is not None:
            command += ["--seed", str(args.seed)]
        if args.fusion is not None:
            command += ["--fusion", args.fusion]
        for index in sorted(args.function):
            command += ["--protect-function", str(index)]
        command += ["--output", str(output), str(source)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if completed.returncode:
            raise ValueError(completed.stderr.strip() or "conversion failed")
        protection = read_protection(output.read_bytes())
        if protection is None or protection["protection_mode"] != args.mode:
            raise ValueError("output protection mode mismatch")
        if protection["fusion_enabled"] != (args.fusion == "on"):
            raise ValueError("output fusion mode mismatch")
        result = {
            "command": command, "engine": str(engine), "engine_sha256": engine_sha,
            "input": str(source), "input_sha256": input_sha,
            "output": str(output), "output_sha256": sha256(output), "output_bytes": output.stat().st_size,
            "protected_function_indices": sorted(args.function), "protection": metadata(protection),
            "conversion_stdout": completed.stdout.strip(),
        }
        with manifest_path.open("x") as destination:
            destination.write(json.dumps(result, indent=2) + "\n")
        print(completed.stdout, end="")
        print(f"Manifest: {manifest_path}")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Protection stopped: {error}\n")


if __name__ == "__main__":
    main()
