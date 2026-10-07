/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#include "parser/ProtectedFusion.h"
#include <stdexcept>
#include <limits>

namespace Walrus {
namespace {
bool branch(ProtectedOpcode opcode)
{
    return opcode == ProtectedOpcode::Jump || opcode == ProtectedOpcode::JumpIfTrue || opcode == ProtectedOpcode::JumpIfFalse;
}

bool combine(const ProtectedInstruction& first, const ProtectedInstruction& second, ProtectedInstruction& result)
{
    if (first.opcode == ProtectedOpcode::I32Add && second.opcode == ProtectedOpcode::MoveI32
        && second.source0 == first.destination && !first.immediate && !second.source1 && !second.immediate) {
        result = first;
        result.opcode = ProtectedOpcode::I32AddMoveI32;
        result.immediate = second.destination;
        return true;
    }
    if (first.opcode == ProtectedOpcode::I64ExtendI32U && second.opcode == ProtectedOpcode::I64Add
        && !first.source1 && !first.immediate && !second.immediate
        && (second.source0 == first.destination || second.source1 == first.destination)) {
        result = { ProtectedOpcode::I64ExtendI32UAddI64, first.source0, 0, second.destination, first.destination };
        if (second.source0 == first.destination) {
            result.source1 = second.source1;
        } else {
            result.source1 = second.source0;
            result.immediate |= UINT64_C(1) << 32; // Preserve original operand order for exact expansion.
        }
        return true;
    }
    return false;
}
} // namespace

ProtectedFusionResult fuseProtectedInstructions(const std::vector<ProtectedInstruction>& input, std::vector<uint32_t>* auxiliary)
{
    if (input.empty() || input.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("invalid fusion input size");
    }
    std::vector<bool> entry(input.size(), false);
    entry[0] = true;
    for (size_t i = 0; i < input.size(); ++i) {
        const auto& instruction = input[i];
        if (static_cast<size_t>(instruction.opcode) >= protectedOpcodeCount || isProtectedFused(instruction.opcode)) {
            throw std::runtime_error("fusion requires base opcodes");
        }
        if (instruction.opcode == ProtectedOpcode::BrTable) {
            const uint64_t start = instruction.destination, size = instruction.immediate + 1;
            if (!auxiliary || instruction.immediate >= UINT32_MAX || start > auxiliary->size() || size > auxiliary->size() - start)
                throw std::runtime_error("invalid fusion branch table");
            for (size_t j = 0; j < size; j++) {
                const auto target = (*auxiliary)[start + j];
                if (target >= input.size()) throw std::runtime_error("fusion branch table target is out of bounds");
                entry[target] = true;
            }
        }
        if (branch(instruction.opcode)) {
            if (instruction.immediate >= input.size()) {
                throw std::runtime_error("fusion branch target is out of bounds");
            }
            entry[instruction.immediate] = true;
        }
        if ((branch(instruction.opcode) || instruction.opcode == ProtectedOpcode::Return
             || instruction.opcode == ProtectedOpcode::Unreachable || instruction.opcode == ProtectedOpcode::BrTable
             || instruction.opcode == ProtectedOpcode::ReturnMany) && i + 1 < input.size()) {
            entry[i + 1] = true;
        }
    }
    ProtectedFusionResult output;
    output.oldToNew.resize(input.size());
    for (size_t i = 0; i < input.size();) {
        ProtectedInstruction combined;
        const bool candidate = i + 1 < input.size() && combine(input[i], input[i + 1], combined);
        output.oldToNew[i] = output.instructions.size();
        if (candidate && !entry[i + 1]) {
            output.oldToNew[i + 1] = output.instructions.size();
            output.instructions.push_back(combined);
            output.fusedCount++;
            i += 2;
        } else {
            output.skippedBranchEntryCount += candidate && entry[i + 1];
            output.instructions.push_back(input[i++]);
        }
    }
    for (auto& instruction : output.instructions) {
        if (branch(instruction.opcode)) {
            instruction.immediate = output.oldToNew[instruction.immediate];
        }
        if (instruction.opcode == ProtectedOpcode::BrTable) {
            for (size_t i = 0; i <= instruction.immediate; i++) {
                auto& target = (*auxiliary)[instruction.destination + i];
                target = output.oldToNew[target];
            }
        }
    }
    return output;
}
} // namespace Walrus
