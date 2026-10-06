/* Compiler-pass checks independent of Wasm lowering and runtime frame allocation. */
#include "parser/ProtectedFusion.h"
#include <cassert>
#include <stdexcept>
using namespace Walrus;
using O = ProtectedOpcode;

int main()
{
    // Entering the move directly must retain the move as a separate instruction.
    std::vector<ProtectedInstruction> entered = {
        { O::JumpIfTrue, 0, 0, 0, 2 }, { O::I32Add, 0, 8, 16, 0 },
        { O::MoveI32, 16, 0, 24, 0 }, { O::Return, 24, 0, 0, 0 }
    };
    auto blocked = fuseProtectedInstructions(entered);
    assert(blocked.fusedCount == 0 && blocked.skippedBranchEntryCount == 1);
    assert(blocked.instructions[0].immediate == 2);
    assert(entered[1].opcode == O::I32Add); // Caller-owned IR stays unchanged.

    // A loop target at the first member is valid; forward and backward edges relocate.
    std::vector<ProtectedInstruction> loop = {
        { O::JumpIfTrue, 0, 0, 0, 6 }, { O::I32Add, 0, 8, 16, 0 },
        { O::MoveI32, 16, 0, 24, 0 }, { O::I64ExtendI32U, 16, 0, 32, 0 },
        { O::I64Add, 40, 32, 48, 0 }, { O::Jump, 0, 0, 0, 1 },
        { O::Return, 48, 0, 0, 0 }
    };
    auto fused = fuseProtectedInstructions(loop);
    assert(fused.fusedCount == 2 && fused.instructions.size() == 5);
    assert(fused.instructions[0].immediate == 4 && fused.instructions[3].immediate == 1);
    assert(fused.instructions[2].immediate == (UINT64_C(1) << 32 | 32));
    assert(fused.instructions[2].source1 == 40);

    loop[4].source0 = 32;
    loop[4].source1 = 32;
    fused = fuseProtectedInstructions(loop);
    assert(fused.instructions[2].immediate == 32 && fused.instructions[2].source1 == 32);
    loop[2].source0 = 12;
    assert(fuseProtectedInstructions(loop).fusedCount == 1);
    loop[0].immediate = loop.size();
    bool rejected = false;
    try { fuseProtectedInstructions(loop); } catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
}
