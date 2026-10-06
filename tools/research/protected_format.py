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
    if version != (1 if name == LEGACY_NAME else 2):
        raise ValueError("unsupported protection format version")
    if abi != 8:
        raise ValueError("incompatible frame ABI")
    stored_checksum, count = reader.number(8), reader.number(4)
    if stored_checksum != checksum:
        raise ValueError("payload/skeleton checksum mismatch")
    mode, algorithm, seed, identity = 0, None, None, None
    if version == 2:
        mode, algorithm = reader.number(4), reader.number(4)
        seed, identity = reader.number(8), reader.number(8)
        if mode not in (0, 1):
            raise ValueError("invalid protection mode")
        if algorithm != 1:
            raise ValueError("unsupported permutation algorithm version")
        if mode == 0 and seed:
            raise ValueError("identity mode does not use a seed")
    if not count or count > reader.remaining() // (24 + 2 * len(OPCODE_NAMES) + INSTRUCTION_SIZE):
        raise ValueError("invalid protected function count")
    functions = []
    seen = set()
    for _ in range(count):
        index, frame, params, results, instructions, mapping_count = [reader.number(4) for _ in range(6)]
        if index in seen:
            raise ValueError("duplicate protected function index")
        seen.add(index)
        if frame < 8 or frame > 65535 or frame % 8 or params * 8 > frame or results > 1:
            raise ValueError("invalid protected frame or signature")
        types = reader.take(params + results)
        if any(value not in (0x7f, 0x7e) for value in types):
            raise ValueError("invalid integer function type")
        if mapping_count != len(OPCODE_NAMES):
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
        for encoded, reserved, *_ in struct.iter_unpack("<HHIIIQ", stream):
            if encoded >= mapping_count or reserved:
                raise ValueError("invalid protected opcode or reserved field")
        functions.append({
            "index": index, "frame_bytes": frame, "parameter_types": list(types[:params]),
            "result_types": list(types[params:]), "instruction_count": instructions,
            "opcode_map": mapping, "instructions": stream,
        })
    if reader.remaining():
        raise ValueError("trailing protected payload data")
    return {
        "group": "G2" if mode else "G1", "format_version": version, "abi_word_bytes": abi,
        "protection_mode": "permuted" if mode else "identity", "seed": seed,
        "permutation_algorithm_version": algorithm,
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
        item = {key: value for key, value in function.items() if key not in ("instructions", "opcode_map")}
        item["opcode_map_sha256"] = hashlib.sha256(struct.pack("<46H", *function["opcode_map"])).hexdigest()
        item["stream_sha256"] = hashlib.sha256(function["instructions"]).hexdigest()
        result["functions"].append(item)
    return result
