/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#include "Walrus.h"
#include "interpreter/Interpreter.h"
#include "interpreter/ProtectedByteCode.h"
#include "runtime/Trap.h"
#include <cinttypes>
#include <cstdio>

namespace Walrus {
namespace {
thread_local bool profileProtected = false;
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
ByteCodeStackOffset executeProtected(ExecutionState& state, const ProtectedFunction& function, uint8_t* bp)
{
    (void)state;
    const size_t count = function.instructions.size() / protectedInstructionSize;
    size_t pc = 0;
    uint64_t dispatchCount = 0;
    uint64_t semanticCount = 0;
    uint64_t fusedCount = 0;
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
            const bool fused = static_cast<size_t>(opcode) >= protectedBaseOpcodeCount;
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
            }
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
#undef EXECUTE_BINARY
#define EXECUTE_UNARY(name, inputType, outputType, expression) \
        case ProtectedOpcode::name: { \
            const inputType a = readFrame<inputType>(bp, source0); \
            writeFrame<outputType>(bp, destination, static_cast<outputType>(expression)); \
            break; \
        }
            FOR_EACH_PROTECTED_UNARY(EXECUTE_UNARY)
#undef EXECUTE_UNARY
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
                                                    const ProtectedFunction& function, StackFrame& frame)
{
    // Profiling is selected once per call; the ordinary instantiation has no counters in its loop.
    return profileProtected ? executeProtected<true>(state, function, frame.bp()) : executeProtected<false>(state, function, frame.bp());
}
} // namespace Walrus
