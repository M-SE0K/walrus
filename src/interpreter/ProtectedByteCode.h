/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#ifndef __WalrusProtectedByteCode__
#define __WalrusProtectedByteCode__

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

// v1/v2 use 46 IDs, v3 uses 48, v4 uses 108; v5 appends scalar floating-point operations.
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
#define FOR_EACH_PROTECTED_INTEGER_BINARY(F) \
    F(I32DivS, int32_t, protectedDiv(a, b)) \
    F(I32DivU, uint32_t, protectedDiv(a, b)) \
    F(I32RemS, int32_t, protectedRem(a, b)) \
    F(I32RemU, uint32_t, protectedRem(a, b)) \
    F(I32Shl, uint32_t, a << (b & 31)) \
    F(I32ShrS, int32_t, protectedShiftRight(a, b)) \
    F(I32ShrU, uint32_t, a >> (b & 31)) \
    F(I32Rotl, uint32_t, protectedRotate(a, b, true)) \
    F(I32Rotr, uint32_t, protectedRotate(a, b, false)) \
    F(I64DivS, int64_t, protectedDiv(a, b)) \
    F(I64DivU, uint64_t, protectedDiv(a, b)) \
    F(I64RemS, int64_t, protectedRem(a, b)) \
    F(I64RemU, uint64_t, protectedRem(a, b)) \
    F(I64Shl, uint64_t, a << (b & 63)) \
    F(I64ShrS, int64_t, protectedShiftRight(a, b)) \
    F(I64ShrU, uint64_t, a >> (b & 63)) \
    F(I64Rotl, uint64_t, protectedRotate(a, b, true)) \
    F(I64Rotr, uint64_t, protectedRotate(a, b, false))

#define FOR_EACH_PROTECTED_INTEGER_UNARY(F) \
    F(I32Clz, uint32_t, protectedCount(a, 0)) \
    F(I32Ctz, uint32_t, protectedCount(a, 1)) \
    F(I32Popcnt, uint32_t, protectedCount(a, 2)) \
    F(I64Clz, uint64_t, protectedCount(a, 0)) \
    F(I64Ctz, uint64_t, protectedCount(a, 1)) \
    F(I64Popcnt, uint64_t, protectedCount(a, 2)) \
    F(I32Extend8S, uint32_t, protectedSignExtend(a, 8)) \
    F(I32Extend16S, uint32_t, protectedSignExtend(a, 16)) \
    F(I64Extend8S, uint64_t, protectedSignExtend(a, 8)) \
    F(I64Extend16S, uint64_t, protectedSignExtend(a, 16)) \
    F(I64Extend32S, uint64_t, protectedSignExtend(a, 32))

#define FOR_EACH_PROTECTED_LOAD(F) \
    F(I32Load, int32_t, int32_t) \
    F(I32Load8S, int8_t, int32_t) \
    F(I32Load8U, uint8_t, uint32_t) \
    F(I32Load16S, int16_t, int32_t) \
    F(I32Load16U, uint16_t, uint32_t) \
    F(I64Load, int64_t, int64_t) \
    F(I64Load8S, int8_t, int64_t) \
    F(I64Load8U, uint8_t, uint64_t) \
    F(I64Load16S, int16_t, int64_t) \
    F(I64Load16U, uint16_t, uint64_t) \
    F(I64Load32S, int32_t, int64_t) \
    F(I64Load32U, uint32_t, uint64_t)

#define FOR_EACH_PROTECTED_STORE(F) \
    F(I32Store, uint32_t, uint32_t) \
    F(I32Store8, uint32_t, uint8_t) \
    F(I32Store16, uint32_t, uint16_t) \
    F(I64Store, uint64_t, uint64_t) \
    F(I64Store8, uint64_t, uint8_t) \
    F(I64Store16, uint64_t, uint16_t) \
    F(I64Store32, uint64_t, uint32_t)

#define FOR_EACH_PROTECTED_FLOAT_BINARY(F) \
    F(F32Add, float, float, canonNaN(a + b)) \
    F(F32Sub, float, float, canonNaN(a - b)) \
    F(F32Mul, float, float, canonNaN(a * b)) \
    F(F32Div, float, float, floatDiv(state, a, b)) \
    F(F32Max, float, float, floatMax(state, a, b)) \
    F(F32Min, float, float, floatMin(state, a, b)) \
    F(F32Copysign, float, float, floatCopysign(state, a, b)) \
    F(F32Eq, float, uint32_t, a == b) \
    F(F32Ne, float, uint32_t, a != b) \
    F(F32Lt, float, uint32_t, a < b) \
    F(F32Le, float, uint32_t, a <= b) \
    F(F32Gt, float, uint32_t, a > b) \
    F(F32Ge, float, uint32_t, a >= b) \
    F(F64Add, double, double, canonNaN(a + b)) \
    F(F64Sub, double, double, canonNaN(a - b)) \
    F(F64Mul, double, double, canonNaN(a * b)) \
    F(F64Div, double, double, floatDiv(state, a, b)) \
    F(F64Max, double, double, floatMax(state, a, b)) \
    F(F64Min, double, double, floatMin(state, a, b)) \
    F(F64Copysign, double, double, floatCopysign(state, a, b)) \
    F(F64Eq, double, uint32_t, a == b) \
    F(F64Ne, double, uint32_t, a != b) \
    F(F64Lt, double, uint32_t, a < b) \
    F(F64Le, double, uint32_t, a <= b) \
    F(F64Gt, double, uint32_t, a > b) \
    F(F64Ge, double, uint32_t, a >= b)

#define FOR_EACH_PROTECTED_FLOAT_UNARY(F) \
    F(F32Sqrt, float, float, floatSqrt(a)) \
    F(F32Ceil, float, float, floatCeil(a)) \
    F(F32Floor, float, float, floatFloor(a)) \
    F(F32Trunc, float, float, floatTrunc(a)) \
    F(F32Nearest, float, float, floatNearest(a)) \
    F(F32Abs, float, float, floatAbs(a)) \
    F(F32Neg, float, float, floatNeg(a)) \
    F(F64Sqrt, double, double, floatSqrt(a)) \
    F(F64Ceil, double, double, floatCeil(a)) \
    F(F64Floor, double, double, floatFloor(a)) \
    F(F64Trunc, double, double, floatTrunc(a)) \
    F(F64Nearest, double, double, floatNearest(a)) \
    F(F64Abs, double, double, floatAbs(a)) \
    F(F64Neg, double, double, floatNeg(a))

#define FOR_EACH_PROTECTED_FLOAT_CONVERT(F) \
    F(I32TruncF32S, float, int32_t, protectedConvert<int32_t>(a)) \
    F(I32TruncF32U, float, uint32_t, protectedConvert<uint32_t>(a)) \
    F(I32TruncF64S, double, int32_t, protectedConvert<int32_t>(a)) \
    F(I32TruncF64U, double, uint32_t, protectedConvert<uint32_t>(a)) \
    F(I64TruncF32S, float, int64_t, protectedConvert<int64_t>(a)) \
    F(I64TruncF32U, float, uint64_t, protectedConvert<uint64_t>(a)) \
    F(I64TruncF64S, double, int64_t, protectedConvert<int64_t>(a)) \
    F(I64TruncF64U, double, uint64_t, protectedConvert<uint64_t>(a)) \
    F(F32ConvertI32S, int32_t, float, protectedConvert<float>(a)) \
    F(F32ConvertI32U, uint32_t, float, protectedConvert<float>(a)) \
    F(F32ConvertI64S, int64_t, float, protectedConvert<float>(a)) \
    F(F32ConvertI64U, uint64_t, float, protectedConvert<float>(a)) \
    F(F64ConvertI32S, int32_t, double, protectedConvert<double>(a)) \
    F(F64ConvertI32U, uint32_t, double, protectedConvert<double>(a)) \
    F(F64ConvertI64S, int64_t, double, protectedConvert<double>(a)) \
    F(F64ConvertI64U, uint64_t, double, protectedConvert<double>(a)) \
    F(I32TruncSatF32S, float, int32_t, intTruncSat<int32_t>(state, a)) \
    F(I32TruncSatF32U, float, uint32_t, intTruncSat<uint32_t>(state, a)) \
    F(I32TruncSatF64S, double, int32_t, intTruncSat<int32_t>(state, a)) \
    F(I32TruncSatF64U, double, uint32_t, intTruncSat<uint32_t>(state, a)) \
    F(I64TruncSatF32S, float, int64_t, intTruncSat<int64_t>(state, a)) \
    F(I64TruncSatF32U, float, uint64_t, intTruncSat<uint64_t>(state, a)) \
    F(I64TruncSatF64S, double, int64_t, intTruncSat<int64_t>(state, a)) \
    F(I64TruncSatF64U, double, uint64_t, intTruncSat<uint64_t>(state, a)) \
    F(F64PromoteF32, float, double, protectedConvert<double>(a)) \
    F(F32DemoteF64, double, float, protectedConvert<float>(a))

// Loads and all other transfers preserve the bit pattern, including NaN payloads.
#define FOR_EACH_PROTECTED_FLOAT_LOAD(F) \
    F(F32Load, uint32_t, uint32_t) \
    F(F64Load, uint64_t, uint64_t)

enum class ProtectedOpcode : uint16_t {
    Const32, Const64, MoveI32, MoveI64, Jump, JumpIfTrue, JumpIfFalse, Return, Unreachable,
#define DECLARE_PROTECTED_OPCODE(name, ...) name,
    FOR_EACH_PROTECTED_BINARY(DECLARE_PROTECTED_OPCODE)
    FOR_EACH_PROTECTED_UNARY(DECLARE_PROTECTED_OPCODE)
#undef DECLARE_PROTECTED_OPCODE
    I32AddMoveI32,
    I64ExtendI32UAddI64,
#define DECLARE_EXTENDED_OPCODE(name, ...) name,
    FOR_EACH_PROTECTED_INTEGER_BINARY(DECLARE_EXTENDED_OPCODE)
    FOR_EACH_PROTECTED_INTEGER_UNARY(DECLARE_EXTENDED_OPCODE)
    FOR_EACH_PROTECTED_LOAD(DECLARE_EXTENDED_OPCODE)
    FOR_EACH_PROTECTED_STORE(DECLARE_EXTENDED_OPCODE)
#undef DECLARE_EXTENDED_OPCODE
    Select32, Select64, BrTable, GlobalGet32, GlobalGet64, GlobalSet32, GlobalSet64,
    MemorySize, MemoryGrow, Call, CallIndirect, ReturnMany,
#define DECLARE_FLOAT_OPCODE(name, ...) name,
    FOR_EACH_PROTECTED_FLOAT_BINARY(DECLARE_FLOAT_OPCODE)
    FOR_EACH_PROTECTED_FLOAT_UNARY(DECLARE_FLOAT_OPCODE)
    FOR_EACH_PROTECTED_FLOAT_CONVERT(DECLARE_FLOAT_OPCODE)
    FOR_EACH_PROTECTED_FLOAT_LOAD(DECLARE_FLOAT_OPCODE)
#undef DECLARE_FLOAT_OPCODE
    Count
};

// Serialized explicitly as little-endian fields, never as a C++ struct dump.
// u16 opcode, u16 reserved, u32 source0, u32 source1, u32 destination, u64 immediate.
static const size_t protectedInstructionSize = 24;
static const size_t protectedOpcodeCount = static_cast<size_t>(ProtectedOpcode::Count);
static const size_t protectedBaseOpcodeCount = 46;
static const size_t protectedV3OpcodeCount = 48;
static const size_t protectedV4OpcodeCount = 108;
inline bool isProtectedFused(ProtectedOpcode opcode)
{
    return opcode == ProtectedOpcode::I32AddMoveI32 || opcode == ProtectedOpcode::I64ExtendI32UAddI64;
}

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
    uint32_t formatVersion = 1;
    bool fusionEnabled = false;
    uint32_t originalInstructionCount = 0;
    uint32_t fusedInstructionCount = 0;
    uint32_t skippedBranchEntryCount = 0;
    uint16_t frameSize;
    uint32_t resultCount;
    uint8_t resultWidth;
    std::array<uint16_t, protectedOpcodeCount> opcodeMap;
    std::vector<uint8_t> instructions;
    std::vector<uint8_t> resultWidths;
    std::vector<uint32_t> auxiliary;
    std::vector<uint16_t> callOffsets;
};
} // namespace Walrus
#endif
