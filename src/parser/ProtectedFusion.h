/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#ifndef __WalrusProtectedFusion__
#define __WalrusProtectedFusion__
#include "interpreter/ProtectedByteCode.h"

namespace Walrus {
struct ProtectedInstruction {
    ProtectedOpcode opcode;
    uint32_t source0;
    uint32_t source1;
    uint32_t destination;
    uint64_t immediate;
};

struct ProtectedFusionResult {
    std::vector<ProtectedInstruction> instructions;
    std::vector<uint32_t> oldToNew;
    uint32_t fusedCount = 0;
    uint32_t skippedBranchEntryCount = 0;
};

// Input uses canonical base opcodes and instruction-index branch targets.
ProtectedFusionResult fuseProtectedInstructions(const std::vector<ProtectedInstruction>& input);
} // namespace Walrus
#endif
