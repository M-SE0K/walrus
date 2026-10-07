/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#include "Walrus.h"
#include "interpreter/Interpreter.h"
#include "interpreter/ProtectedByteCode.h"
#include "runtime/Trap.h"
#include "runtime/Memory.h"
#include "runtime/Global.h"
#include "runtime/Table.h"
#include "util/BitOperation.h"
#include "util/MathOperation.h"
#include <limits>
#include <type_traits>
#include <cinttypes>
#include <cstdio>

namespace Walrus {
namespace {
thread_local bool profileProtected = false;

// Use the same conversion rules and helpers as the ordinary interpreter.
template <typename R, typename T> R protectedConvert(T value)
{
    if (std::is_integral<R>::value && std::is_floating_point<T>::value && isNaN(value))
        Trap::throwException("invalid conversion to integer");
    if (!canConvert<R>(value)) Trap::throwException("integer overflow");
    return convert<R>(value);
}

template <typename T> T protectedDiv(T a, T b)
{
    if (!b) Trap::throwException("integer divide by zero");
    if (std::is_signed<T>::value && a == std::numeric_limits<T>::min() && b == static_cast<T>(-1))
        Trap::throwException("integer overflow");
    return a / b;
}
template <typename T> T protectedRem(T a, T b)
{
    if (!b) Trap::throwException("integer divide by zero");
    if (std::is_signed<T>::value && a == std::numeric_limits<T>::min() && b == static_cast<T>(-1)) return 0;
    return a % b;
}
template <typename T> T protectedShiftRight(T a, T b)
{
    using U = typename std::make_unsigned<T>::type;
    const unsigned bits = sizeof(T) * 8, shift = static_cast<U>(b) & (bits - 1);
    U result = static_cast<U>(a) >> shift;
    if (a < 0 && shift) result |= ~U(0) << (bits - shift);
    return static_cast<T>(result);
}
template <typename T> T protectedRotate(T a, T b, bool left)
{
    const unsigned mask = sizeof(T) * 8 - 1, shift = b & mask;
    return left ? (a << shift) | (a >> ((0 - shift) & mask)) : (a >> shift) | (a << ((0 - shift) & mask));
}
template <typename T> T protectedCount(T a, unsigned kind)
{
    return static_cast<T>(kind == 0 ? clz(a) : (kind == 1 ? ctz(a) : popCount(a)));
}
template <typename T> T protectedSignExtend(T a, unsigned bits)
{
    const T sign = T(1) << (bits - 1), mask = (T(1) << bits) - 1;
    return ((a & mask) ^ sign) - sign;
}
template <typename T>
T readFrame(const uint8_t* frame, uint32_t offset)
{
    T value;
    memcpy(&value, frame + offset, sizeof(T));
    return value;
}

template <typename T>
void writeFrame(uint8_t* frame, uint32_t offset, T value)
{
    memcpy(frame + offset, &value, sizeof(T));
}

template <bool Profile>
ByteCodeStackOffset executeProtected(ExecutionState& state, const ProtectedFunction& function, uint8_t* bp, uint8_t* results)
{
    (void)state;
    const size_t count = function.instructions.size() / protectedInstructionSize;
    size_t pc = 0;
    uint64_t dispatchCount = 0;
    uint64_t semanticCount = 0;
    uint64_t fusedCount = 0;
    Instance* instance = state.currentFunction().value()->asDefinedFunction()->instance();
    // All fields, frame accesses, and control-flow edges were checked by the loader.
    while (pc < count) {
        const uint8_t* code = function.instructions.data() + pc * protectedInstructionSize;
        const auto opcode = static_cast<ProtectedOpcode>(function.opcodeMap[readProtectedNumber(code, 2)]);
        const uint32_t source0 = readProtectedNumber(code + 4, 4);
        const uint32_t source1 = readProtectedNumber(code + 8, 4);
        const uint32_t destination = readProtectedNumber(code + 12, 4);
        const uint64_t immediate = readProtectedNumber(code + 16, 8);
        pc++;
        if (Profile) {
            const bool fused = isProtectedFused(opcode);
            dispatchCount++;
            semanticCount += fused ? 2 : 1;
            fusedCount += fused;
        }
        switch (opcode) {
        case ProtectedOpcode::Const32:
            writeFrame<uint32_t>(bp, destination, static_cast<uint32_t>(immediate));
            break;
        case ProtectedOpcode::Const64:
            writeFrame<uint64_t>(bp, destination, immediate);
            break;
        case ProtectedOpcode::MoveI32:
            writeFrame<uint32_t>(bp, destination, readFrame<uint32_t>(bp, source0));
            break;
        case ProtectedOpcode::MoveI64:
            writeFrame<uint64_t>(bp, destination, readFrame<uint64_t>(bp, source0));
            break;
        case ProtectedOpcode::Jump:
            pc = immediate;
            break;
        case ProtectedOpcode::JumpIfTrue:
            if (readFrame<uint32_t>(bp, source0)) {
                pc = immediate;
            }
            break;
        case ProtectedOpcode::JumpIfFalse:
            if (!readFrame<uint32_t>(bp, source0)) {
                pc = immediate;
            }
            break;
        case ProtectedOpcode::Return:
            if (function.resultCount) {
                const uint64_t value = function.resultWidth == 4 ? readFrame<uint32_t>(bp, source0) : readFrame<uint64_t>(bp, source0);
                // Normalize packed i32 locals to a full word for the existing call ABI.
                writeFrame<uint64_t>(bp, 0, value);
                writeFrame<uint64_t>(results, 0, value);
            }
            goto completed;
        case ProtectedOpcode::ReturnMany:
            for (size_t i = 0; i < function.resultCount; i++) {
                const uint32_t offset = function.auxiliary[immediate + i];
                const uint64_t value = function.resultWidths[i] == 4 ? readFrame<uint32_t>(bp, offset) : readFrame<uint64_t>(bp, offset);
                writeFrame<uint64_t>(results, i * 8, value);
            }
        completed:
            if (Profile) {
                fprintf(stderr, "WALRUS_PROTECTED_PROFILE {\"function_index\":%u,\"dispatch_count\":%" PRIu64 ",\"semantic_instruction_count\":%" PRIu64 ",\"fused_dispatch_count\":%" PRIu64 "}\n",
                        function.functionIndex, dispatchCount, semanticCount, fusedCount);
            }
            return 0;
        case ProtectedOpcode::Unreachable:
            Trap::throwException("unreachable executed");
            break;
        case ProtectedOpcode::I32AddMoveI32: {
            const uint32_t a = readFrame<uint32_t>(bp, source0);
            const uint32_t b = readFrame<uint32_t>(bp, source1);
            writeFrame<uint32_t>(bp, destination, a + b);
            writeFrame<uint32_t>(bp, static_cast<uint32_t>(immediate), readFrame<uint32_t>(bp, destination));
            break;
        }
        case ProtectedOpcode::I64ExtendI32UAddI64: {
            const uint32_t temporary = static_cast<uint32_t>(immediate);
            writeFrame<uint64_t>(bp, temporary, static_cast<uint64_t>(readFrame<uint32_t>(bp, source0)));
            // The other input can overlap the temporary: read it after the extension write.
            const uint64_t extended = readFrame<uint64_t>(bp, temporary);
            const uint64_t other = readFrame<uint64_t>(bp, source1);
            writeFrame<uint64_t>(bp, destination, extended + other);
            break;
        }
#define EXECUTE_BINARY(name, inputType, outputType, expression) \
        case ProtectedOpcode::name: { \
            const inputType a = readFrame<inputType>(bp, source0); \
            const inputType b = readFrame<inputType>(bp, source1); \
            writeFrame<outputType>(bp, destination, static_cast<outputType>(expression)); \
            break; \
        }
            FOR_EACH_PROTECTED_BINARY(EXECUTE_BINARY)
            FOR_EACH_PROTECTED_FLOAT_BINARY(EXECUTE_BINARY)
#undef EXECUTE_BINARY
#define EXECUTE_UNARY(name, inputType, outputType, expression) \
        case ProtectedOpcode::name: { \
            const inputType a = readFrame<inputType>(bp, source0); \
            writeFrame<outputType>(bp, destination, static_cast<outputType>(expression)); \
            break; \
        }
            FOR_EACH_PROTECTED_UNARY(EXECUTE_UNARY)
            FOR_EACH_PROTECTED_FLOAT_UNARY(EXECUTE_UNARY)
            FOR_EACH_PROTECTED_FLOAT_CONVERT(EXECUTE_UNARY)
#undef EXECUTE_UNARY
#define EXECUTE_EXTENDED_BINARY(name, type, expression) \
        case ProtectedOpcode::name: { \
            const type a = readFrame<type>(bp, source0), b = readFrame<type>(bp, source1); \
            writeFrame<type>(bp, destination, expression); break; \
        }
            FOR_EACH_PROTECTED_INTEGER_BINARY(EXECUTE_EXTENDED_BINARY)
#undef EXECUTE_EXTENDED_BINARY
#define EXECUTE_EXTENDED_UNARY(name, type, expression) \
        case ProtectedOpcode::name: { const type a = readFrame<type>(bp, source0); \
            writeFrame<type>(bp, destination, expression); break; }
            FOR_EACH_PROTECTED_INTEGER_UNARY(EXECUTE_EXTENDED_UNARY)
#undef EXECUTE_EXTENDED_UNARY
#define EXECUTE_LOAD(name, readType, writeType) \
        case ProtectedOpcode::name: { readType value; \
            instance->memory(source1)->load(state, readFrame<uint32_t>(bp, source0), static_cast<uint32_t>(immediate), &value); \
            writeFrame<writeType>(bp, destination, static_cast<writeType>(value)); break; }
            FOR_EACH_PROTECTED_LOAD(EXECUTE_LOAD)
            FOR_EACH_PROTECTED_FLOAT_LOAD(EXECUTE_LOAD)
#undef EXECUTE_LOAD
#define EXECUTE_STORE(name, readType, writeType) \
        case ProtectedOpcode::name: { \
            const writeType value = static_cast<writeType>(readFrame<readType>(bp, source1)); \
            instance->memory(destination)->store(state, readFrame<uint32_t>(bp, source0), static_cast<uint32_t>(immediate), value); break; }
            FOR_EACH_PROTECTED_STORE(EXECUTE_STORE)
#undef EXECUTE_STORE
        case ProtectedOpcode::Select32:
            writeFrame<uint32_t>(bp, destination, readFrame<uint32_t>(bp, immediate) ? readFrame<uint32_t>(bp, source0) : readFrame<uint32_t>(bp, source1));
            break;
        case ProtectedOpcode::Select64:
            writeFrame<uint64_t>(bp, destination, readFrame<uint32_t>(bp, immediate) ? readFrame<uint64_t>(bp, source0) : readFrame<uint64_t>(bp, source1));
            break;
        case ProtectedOpcode::BrTable: {
            const uint32_t selector = readFrame<uint32_t>(bp, source0);
            pc = function.auxiliary[destination + std::min<uint64_t>(selector, immediate)];
            break;
        }
        case ProtectedOpcode::GlobalGet32:
            instance->global(immediate)->value().writeNBytesToMemory<4>(bp + destination); break;
        case ProtectedOpcode::GlobalGet64:
            instance->global(immediate)->value().writeNBytesToMemory<8>(bp + destination); break;
        case ProtectedOpcode::GlobalSet32:
            instance->global(immediate)->value().readFromStack<4>(bp + source0); break;
        case ProtectedOpcode::GlobalSet64:
            instance->global(immediate)->value().readFromStack<8>(bp + source0); break;
        case ProtectedOpcode::MemorySize:
            writeFrame<uint32_t>(bp, destination, instance->memory(immediate)->sizeInPageSize()); break;
        case ProtectedOpcode::MemoryGrow: {
            Memory* memory = instance->memory(immediate);
            const auto previous = memory->sizeInPageSize();
            const bool grown = memory->grow(static_cast<uint64_t>(readFrame<uint32_t>(bp, source0)) * Memory::s_memoryPageSize);
            writeFrame<uint32_t>(bp, destination, grown ? previous : UINT32_MAX); break;
        }
        case ProtectedOpcode::Call:
        case ProtectedOpcode::CallIndirect: {
            Function* target;
            const FunctionType* type;
            if (opcode == ProtectedOpcode::Call) {
                target = instance->function(immediate);
                type = target->functionType();
            } else {
                Table* table = instance->table(source1);
                const uint32_t element = readFrame<uint32_t>(bp, source0);
                if (element >= table->size()) Trap::throwException("undefined element");
                target = reinterpret_cast<Function*>(table->uncheckedGetElement(element));
                if (Value::isNull(target)) Trap::throwException("uninitialized element " + std::to_string(element));
                type = instance->module()->functionType(immediate);
                if (!target->functionType()->equals(type)) Trap::throwException("indirect call type mismatch");
            }
            target->interpreterCall(state, bp, const_cast<uint16_t*>(function.callOffsets.data() + destination),
                                    type->paramStackSize() / 8, type->resultStackSize() / 8);
            break;
        }
        default:
            Trap::throwException("invalid protected opcode");
        }
    }
    Trap::throwException("protected function fell through without returning");
    return 0;
}
} // namespace

void Interpreter::setProtectedProfiling(bool enabled)
{
    profileProtected = enabled;
}

ByteCodeStackOffset Interpreter::interpretProtected(ExecutionState& state,
                                                    const ProtectedFunction& function, StackFrame& frame, uint8_t* results)
{
    // Profiling is selected once per call; the ordinary instantiation has no counters in its loop.
    return profileProtected ? executeProtected<true>(state, function, frame.bp(), results) : executeProtected<false>(state, function, frame.bp(), results);
}
} // namespace Walrus
