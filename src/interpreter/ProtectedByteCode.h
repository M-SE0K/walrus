/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#ifndef __WalrusProtectedByteCode__
#define __WalrusProtectedByteCode__

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

// The base order is shared by formats v1/v2; v3 appends two fused opcodes.
// These IDs are independent of ByteCode::Opcode.
// Arithmetic uses unsigned operands to preserve Wasm's wrapping semantics.
#define FOR_EACH_PROTECTED_BINARY(F) \
    F(I32Add, uint32_t, uint32_t, a + b) \
    F(I32Sub, uint32_t, uint32_t, a - b) \
    F(I32Mul, uint32_t, uint32_t, a * b) \
    F(I32And, uint32_t, uint32_t, a & b) \
    F(I32Or, uint32_t, uint32_t, a | b) \
    F(I32Xor, uint32_t, uint32_t, a ^ b) \
    F(I32Eq, uint32_t, uint32_t, a == b) \
    F(I32Ne, uint32_t, uint32_t, a != b) \
    F(I32LtS, int32_t, uint32_t, a < b) \
    F(I32LtU, uint32_t, uint32_t, a < b) \
    F(I32GtS, int32_t, uint32_t, a > b) \
    F(I32GtU, uint32_t, uint32_t, a > b) \
    F(I32LeS, int32_t, uint32_t, a <= b) \
    F(I32LeU, uint32_t, uint32_t, a <= b) \
    F(I32GeS, int32_t, uint32_t, a >= b) \
    F(I32GeU, uint32_t, uint32_t, a >= b) \
    F(I64Add, uint64_t, uint64_t, a + b) \
    F(I64Sub, uint64_t, uint64_t, a - b) \
    F(I64Mul, uint64_t, uint64_t, a * b) \
    F(I64And, uint64_t, uint64_t, a & b) \
    F(I64Or, uint64_t, uint64_t, a | b) \
    F(I64Xor, uint64_t, uint64_t, a ^ b) \
    F(I64Eq, uint64_t, uint32_t, a == b) \
    F(I64Ne, uint64_t, uint32_t, a != b) \
    F(I64LtS, int64_t, uint32_t, a < b) \
    F(I64LtU, uint64_t, uint32_t, a < b) \
    F(I64GtS, int64_t, uint32_t, a > b) \
    F(I64GtU, uint64_t, uint32_t, a > b) \
    F(I64LeS, int64_t, uint32_t, a <= b) \
    F(I64LeU, uint64_t, uint32_t, a <= b) \
    F(I64GeS, int64_t, uint32_t, a >= b) \
    F(I64GeU, uint64_t, uint32_t, a >= b)

#define FOR_EACH_PROTECTED_UNARY(F) \
    F(I32Eqz, uint32_t, uint32_t, a == 0) \
    F(I64Eqz, uint64_t, uint32_t, a == 0) \
    F(I32WrapI64, uint64_t, uint32_t, static_cast<uint32_t>(a)) \
    F(I64ExtendI32U, uint32_t, uint64_t, static_cast<uint64_t>(a)) \
    F(I64ExtendI32S, int32_t, uint64_t, static_cast<uint64_t>(static_cast<int64_t>(a)))

namespace Walrus {
enum class ProtectedOpcode : uint16_t {
    Const32, Const64, MoveI32, MoveI64, Jump, JumpIfTrue, JumpIfFalse, Return, Unreachable,
#define DECLARE_PROTECTED_OPCODE(name, ...) name,
    FOR_EACH_PROTECTED_BINARY(DECLARE_PROTECTED_OPCODE)
    FOR_EACH_PROTECTED_UNARY(DECLARE_PROTECTED_OPCODE)
#undef DECLARE_PROTECTED_OPCODE
    I32AddMoveI32,
    I64ExtendI32UAddI64,
    Count
};

// Serialized explicitly as little-endian fields, never as a C++ struct dump.
// u16 opcode, u16 reserved, u32 source0, u32 source1, u32 destination, u64 immediate.
static const size_t protectedInstructionSize = 24;
static const size_t protectedOpcodeCount = static_cast<size_t>(ProtectedOpcode::Count);
static const size_t protectedBaseOpcodeCount = 46;

inline uint64_t readProtectedNumber(const uint8_t* data, size_t bytes)
{
    uint64_t value = 0;
    for (size_t i = 0; i < bytes; i++) {
        value |= static_cast<uint64_t>(data[i]) << (i * 8);
    }
    return value;
}

struct ProtectedFunction {
    uint32_t functionIndex = 0;
    uint32_t opcodeCount = protectedBaseOpcodeCount;
    bool fusionEnabled = false;
    uint32_t originalInstructionCount = 0;
    uint32_t fusedInstructionCount = 0;
    uint32_t skippedBranchEntryCount = 0;
    uint16_t frameSize;
    uint32_t resultCount;
    uint8_t resultWidth;
    std::array<uint16_t, protectedOpcodeCount> opcodeMap;
    std::vector<uint8_t> instructions;
};
} // namespace Walrus
#endif
