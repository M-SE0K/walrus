#!/usr/bin/env python3
"""Recover canonical protected operations using mapping tables in the deployed Wasm."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import time

from protected_format import OPCODE_NAMES, canonicalize, expand, expand_auxiliary, metadata, read_protection


def recover(data, include_instructions=True):
    start = time.perf_counter_ns()
    protection = read_protection(data)
    if protection is None:
        raise ValueError("no protection section")
    result = {
        "analysis": "stored_mapping_recovery", "wasm_sha256": hashlib.sha256(data).hexdigest(),
        "protection": metadata(protection), "functions": [],
    }
    recovered_count = 0
    for function in protection["functions"]:
        canonical, sources = expand(function)
        auxiliary = expand_auxiliary(function, sources)
        auxiliary_bytes = struct.pack(f"<{len(auxiliary)}I", *auxiliary)
        instructions, counts = [], Counter()
        for pc, fields in enumerate(struct.iter_unpack("<HHIIIQ", canonical)):
            opcode, _, source0, source1, destination, immediate = fields
            name = OPCODE_NAMES[opcode]
            counts[name] += 1
            if include_instructions:
                instructions.append({
                    "pc": pc, "source_stored_pc": sources[pc],
                    "encoded_opcode": struct.unpack_from("<H", function["instructions"], sources[pc] * 24)[0],
                    "opcode": opcode, "name": name, "source0": source0, "source1": source1,
                    "destination": destination, "immediate": immediate,
                })
        item = {
            "index": function["index"], "instruction_count": len(sources),
            "stored_instruction_count": function["instruction_count"],
            "fused_instruction_count": function["fused_instruction_count"],
            "stored_canonical_stream_sha256": hashlib.sha256(canonicalize(function)).hexdigest(),
            "canonical_stream_sha256": hashlib.sha256(canonical).hexdigest(),
            "canonical_auxiliary_sha256": hashlib.sha256(auxiliary_bytes).hexdigest(),
            "canonical_program_sha256": hashlib.sha256(canonical + auxiliary_bytes).hexdigest(),
            "opcode_counts": dict(sorted(counts.items())),
        }
        if include_instructions:
            item["instructions"] = instructions
            item["auxiliary"] = auxiliary
        result["functions"].append(item)
        recovered_count += len(sources)
    result["recovered_instruction_count"] = recovered_count
    # Structural recovery coverage, not a source-code recovery or protection-strength score.
    result["instruction_mapping_coverage"] = 1.0
    result["decode_ms"] = (time.perf_counter_ns() - start) / 1_000_000
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wasm", type=Path)
    parser.add_argument("--output", type=Path, help="new JSON file; stdout if omitted")
    parser.add_argument("--summary", action="store_true", help="omit individual instructions")
    args = parser.parse_args()
    try:
        result = recover(args.wasm.read_bytes(), not args.summary)
        encoded = json.dumps(result, indent=2) + "\n"
        if args.output:
            with args.output.open("x") as output:
                output.write(encoded)
        else:
            print(encoded, end="")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Recovery stopped: {error}\n")


if __name__ == "__main__":
    main()
