"""Public protected-format reader for metadata and stored-table recovery.

This is a structural reader, not a replacement for Walrus's typed operand validator.
It uses only the deployed Wasm, never a seed manifest or the original function IR.
"""

import hashlib
import struct

HEADER = b"\x00asm\x01\x00\x00\x00"
LEGACY_NAME = b"walrus.protected.g1"
COMMON_NAME = b"walrus.protected"
INSTRUCTION_SIZE = 24
BINARY_NAMES = ("Add", "Sub", "Mul", "And", "Or", "Xor", "Eq", "Ne",
                "LtS", "LtU", "GtS", "GtU", "LeS", "LeU", "GeS", "GeU")
OPCODE_NAMES = ["Const32", "Const64", "MoveI32", "MoveI64", "Jump",
                "JumpIfTrue", "JumpIfFalse", "Return", "Unreachable"]
OPCODE_NAMES += [width + name for width in ("I32", "I64") for name in BINARY_NAMES]
OPCODE_NAMES += ["I32Eqz", "I64Eqz", "I32WrapI64", "I64ExtendI32U", "I64ExtendI32S"]
BASE_OPCODE_COUNT = len(OPCODE_NAMES)
OPCODE_NAMES += ["I32AddMoveI32", "I64ExtendI32UAddI64"]
V3_OPCODE_COUNT = len(OPCODE_NAMES)
OPCODE_NAMES += [width + name for width in ("I32", "I64") for name in
                 ("DivS", "DivU", "RemS", "RemU", "Shl", "ShrS", "ShrU", "Rotl", "Rotr")]
OPCODE_NAMES += [width + name for width in ("I32", "I64") for name in ("Clz", "Ctz", "Popcnt")]
OPCODE_NAMES += ["I32Extend8S", "I32Extend16S", "I64Extend8S", "I64Extend16S", "I64Extend32S"]
OPCODE_NAMES += ["I32Load", "I32Load8S", "I32Load8U", "I32Load16S", "I32Load16U",
                 "I64Load", "I64Load8S", "I64Load8U", "I64Load16S", "I64Load16U", "I64Load32S", "I64Load32U"]
OPCODE_NAMES += ["I32Store", "I32Store8", "I32Store16", "I64Store", "I64Store8", "I64Store16", "I64Store32"]
OPCODE_NAMES += ["Select32", "Select64", "BrTable", "GlobalGet32", "GlobalGet64", "GlobalSet32", "GlobalSet64",
                 "MemorySize", "MemoryGrow", "Call", "CallIndirect", "ReturnMany"]
V4_OPCODE_COUNT = len(OPCODE_NAMES)
OPCODE_NAMES += [width + name for width in ("F32", "F64") for name in
                 ("Add", "Sub", "Mul", "Div", "Max", "Min", "Copysign", "Eq", "Ne", "Lt", "Le", "Gt", "Ge")]
OPCODE_NAMES += [width + name for width in ("F32", "F64") for name in
                 ("Sqrt", "Ceil", "Floor", "Trunc", "Nearest", "Abs", "Neg")]
OPCODE_NAMES += [out + "Trunc" + source + sign for out in ("I32", "I64")
                 for source in ("F32", "F64") for sign in ("S", "U")]
OPCODE_NAMES += [out + "Convert" + source + sign for out in ("F32", "F64")
                 for source in ("I32", "I64") for sign in ("S", "U")]
OPCODE_NAMES += [out + "TruncSat" + source + sign for out in ("I32", "I64")
                 for source in ("F32", "F64") for sign in ("S", "U")]
OPCODE_NAMES += ["F64PromoteF32", "F32DemoteF64", "F32Load", "F64Load"]
OPCODES = {name: index for index, name in enumerate(OPCODE_NAMES)}


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def remaining(self):
        return len(self.data) - self.offset

    def take(self, size):
        if size < 0 or size > self.remaining():
            raise ValueError("truncated protected data")
        start = self.offset
        self.offset += size
        return self.data[start:self.offset]

    def number(self, size):
        return int.from_bytes(self.take(size), "little")

    def uleb(self):
        value = 0
        for i in range(5):
            byte = self.number(1)
            if i == 4 and byte & 0xf0:
                raise ValueError("invalid u32 LEB128")
            value |= (byte & 0x7f) << (i * 7)
            if not byte & 0x80:
                return value
        raise ValueError("invalid u32 LEB128")


def fnv64(data, value=14695981039346656037):
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def read_protection(data):
    if data[:8] != HEADER:
        raise ValueError("expected a core Wasm module")
    sections = Reader(data[8:])
    checksum = fnv64(HEADER)
    payload = name = None
    while sections.remaining():
        start = sections.offset
        kind = sections.number(1)
        body = sections.take(sections.uleb())
        if kind:
            checksum = fnv64(sections.data[start:sections.offset], checksum)
        else:
            custom = Reader(body)
            section_name = custom.take(custom.uleb())
            if section_name in (LEGACY_NAME, COMMON_NAME):
                if payload is not None:
                    raise ValueError("duplicate protection section")
                name = section_name
                payload = custom.take(custom.remaining())
    if payload is None:
        return None
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError("protected payload is too large")
    reader = Reader(payload)
    if reader.take(4) != b"WGP1":
        raise ValueError("invalid protection magic")
    version, abi = reader.number(4), reader.number(4)
    if version not in ((1,) if name == LEGACY_NAME else (2, 3, 4, 5)):
        raise ValueError("unsupported protection format version")
    if abi != 8:
        raise ValueError("incompatible frame ABI")
    stored_checksum, count = reader.number(8), reader.number(4)
    if stored_checksum != checksum:
        raise ValueError("payload/skeleton checksum mismatch")
    mode, algorithm, seed, identity = 0, None, None, None
    if version >= 2:
        mode, algorithm = reader.number(4), reader.number(4)
        seed, identity = reader.number(8), reader.number(8)
        if mode not in (0, 1):
            raise ValueError("invalid protection mode")
        if algorithm != 1:
            raise ValueError("unsupported permutation algorithm version")
        if mode == 0 and seed:
            raise ValueError("identity mode does not use a seed")
    fusion, fusion_algorithm = False, None
    if version >= 3:
        enabled, fusion_algorithm = reader.number(4), reader.number(4)
        if enabled not in (0, 1) or fusion_algorithm != 1 or (enabled and mode != 1):
            raise ValueError("invalid fusion mode or algorithm version")
        fusion = bool(enabled)
    opcode_count = len(OPCODE_NAMES) if version == 5 else (V4_OPCODE_COUNT if version == 4 else (V3_OPCODE_COUNT if version == 3 else BASE_OPCODE_COUNT))
    record_size = 40 if version >= 4 else (36 if version == 3 else 24)
    if not count or count > reader.remaining() // (record_size + 2 * opcode_count + INSTRUCTION_SIZE):
        raise ValueError("invalid protected function count")
    functions = []
    seen = set()
    for _ in range(count):
        index, frame, params, results, instructions, mapping_count = [reader.number(4) for _ in range(6)]
        original, fused, skipped = instructions, 0, 0
        if version >= 3:
            original, fused, skipped = [reader.number(4) for _ in range(3)]
        auxiliary_count = reader.number(4) if version >= 4 else 0
        if index in seen:
            raise ValueError("duplicate protected function index")
        seen.add(index)
        if frame < 8 or frame > 65535 or frame % 8 or params * 8 > frame or (version < 4 and results > 1):
            raise ValueError("invalid protected frame or signature")
        types = reader.take(params + results)
        if any(value not in ((0x7f, 0x7e, 0x7d, 0x7c) if version >= 5 else (0x7f, 0x7e)) for value in types):
            raise ValueError("invalid protected function type")
        if mapping_count != opcode_count:
            raise ValueError("invalid opcode mapping size")
        mapping = [reader.number(2) for _ in range(mapping_count)]
        if sorted(mapping) != list(range(mapping_count)):
            raise ValueError("opcode mapping is not a bijection")
        identity_map = mapping == list(range(mapping_count))
        if mode == 0 and not identity_map:
            raise ValueError("G1 requires an identity opcode mapping")
        if mode == 1 and identity_map:
            raise ValueError("permuted mode requires a non-identity opcode mapping")
        if not instructions or instructions > reader.remaining() // INSTRUCTION_SIZE:
            raise ValueError("invalid protected instruction count")
        stream = reader.take(instructions * INSTRUCTION_SIZE)
        if auxiliary_count > reader.remaining() // 4:
            raise ValueError("invalid protected auxiliary count")
        auxiliary = [reader.number(4) for _ in range(auxiliary_count)]
        patterns = {"I32AddMoveI32": 0, "I64ExtendI32UAddI64": 0}
        for encoded, reserved, source0, source1, destination, immediate in struct.iter_unpack("<HHIIIQ", stream):
            if encoded >= mapping_count or reserved:
                raise ValueError("invalid protected opcode or reserved field")
            opcode = mapping[encoded]
            if opcode in (46, 47):
                if not fusion:
                    raise ValueError("fused opcode requires fusion mode")
                if immediate >> (32 if opcode == 46 else 33):
                    raise ValueError("invalid fused immediate")
                patterns[OPCODE_NAMES[opcode]] += 1
            if opcode in (4, 5, 6) and immediate >= instructions:
                raise ValueError("branch target is out of bounds")
            if opcode == OPCODES["BrTable"]:
                if immediate >= 0xffffffff or destination > len(auxiliary) or immediate + 1 > len(auxiliary) - destination:
                    raise ValueError("invalid branch table auxiliary range")
                if any(target >= instructions for target in auxiliary[destination:destination + immediate + 1]):
                    raise ValueError("branch table target is out of bounds")
            if opcode == OPCODES["ReturnMany"] and (immediate > len(auxiliary) or results > len(auxiliary) - immediate):
                raise ValueError("invalid return auxiliary range")
        if fused != sum(patterns.values()) or original != instructions + fused or skipped > original or (not fusion and skipped):
            raise ValueError("invalid fusion statistics")
        functions.append({
            "index": index, "frame_bytes": frame, "parameter_types": list(types[:params]),
            "result_types": list(types[params:]), "instruction_count": instructions,
            "opcode_map": mapping, "instructions": stream,
            "auxiliary": auxiliary, "auxiliary_count": auxiliary_count,
            "original_instruction_count": original, "fused_instruction_count": fused,
            "skipped_branch_entry_count": skipped, "fusion_patterns": patterns,
            "instruction_reduction_ratio": (original - instructions) / original,
        })
    if reader.remaining():
        raise ValueError("trailing protected payload data")
    return {
        "group": "G3" if fusion else ("G2" if mode else "G1"), "format_version": version, "abi_word_bytes": abi,
        "protection_mode": "permuted" if mode else "identity", "seed": seed,
        "permutation_algorithm_version": algorithm,
        "fusion_enabled": fusion, "fusion_algorithm_version": fusion_algorithm,
        "input_identity_fnv64": None if identity is None else f"{identity:016x}",
        "skeleton_checksum": f"{checksum:016x}", "payload_bytes": len(payload),
        "functions": functions,
    }


def canonicalize(function):
    """Undo only opcode permutation; preserve operands, constants and branch indices."""
    output = bytearray(function["instructions"])
    for offset in range(0, len(output), INSTRUCTION_SIZE):
        encoded = struct.unpack_from("<H", output, offset)[0]
        struct.pack_into("<H", output, offset, function["opcode_map"][encoded])
    return bytes(output)


def metadata(protection):
    if protection is None:
        return None
    result = {key: value for key, value in protection.items() if key != "functions"}
    result["functions"] = []
    for function in protection["functions"]:
        item = {key: value for key, value in function.items() if key not in ("instructions", "opcode_map", "auxiliary")}
        item["opcode_map_sha256"] = hashlib.sha256(struct.pack(f"<{len(function['opcode_map'])}H", *function["opcode_map"])).hexdigest()
        item["stream_sha256"] = hashlib.sha256(function["instructions"]).hexdigest()
        item["auxiliary_sha256"] = hashlib.sha256(struct.pack(f"<{len(function['auxiliary'])}I", *function["auxiliary"])).hexdigest()
        result["functions"].append(item)
    return result


def expand(function):
    """Undo permutation and fusion, including relocation of expanded branch targets.

    Returns the base stream and its stored-PC provenance; no original IR is needed.
    """
    stored = list(struct.iter_unpack("<HHIIIQ", canonicalize(function)))
    expanded, sources, positions = [], [], []
    for pc, fields in enumerate(stored):
        opcode, _, source0, source1, destination, immediate = fields
        positions.append(len(expanded))
        if opcode == 46:
            pair = [(9, 0, source0, source1, destination, 0),
                    (2, 0, destination, 0, immediate, 0)]
        elif opcode == 47:
            temporary = immediate & 0xffffffff
            left, right = (source1, temporary) if immediate >> 32 else (temporary, source1)
            pair = [(44, 0, source0, 0, temporary, 0),
                    (25, 0, left, right, destination, 0)]
        else:
            pair = [fields]
        expanded.extend(pair)
        sources.extend([pc] * len(pair))
    output = bytearray()
    for fields in expanded:
        if fields[0] in (4, 5, 6):
            fields = (*fields[:5], positions[fields[5]])
        output.extend(struct.pack("<HHIIIQ", *fields))
    return bytes(output), sources


def expand_auxiliary(function, sources):
    """Relocate br_table entries from stored PCs to expanded base PCs."""
    output = list(function["auxiliary"])
    positions = {}
    for expanded_pc, stored_pc in enumerate(sources):
        positions.setdefault(stored_pc, expanded_pc)
    for opcode, _, _, _, start, size in struct.iter_unpack("<HHIIIQ", canonicalize(function)):
        if opcode == OPCODES["BrTable"]:
            for index in range(start, start + size + 1):
                output[index] = positions[function["auxiliary"][index]]
    return output
