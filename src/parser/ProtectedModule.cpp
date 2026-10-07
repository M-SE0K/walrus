/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#include "Walrus.h"
#include "parser/ProtectedModule.h"
#include "parser/ProtectedFusion.h"
#include "parser/WASMParser.h"
#include "interpreter/ByteCode.h"
#include "interpreter/ProtectedByteCode.h"
#include <map>
#include <stdexcept>

namespace Walrus {
namespace {
const char sectionName[] = "walrus.protected.g1";
const char commonSectionName[] = "walrus.protected";
const uint8_t stubBody[] = { 0, 0, 0x0b }; // no locals; unreachable; end
const size_t payloadLimit = 64 * 1024 * 1024;

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

bool isProtectionSection(const std::string& name)
{
    return name == sectionName || name == commonSectionName;
}

uint64_t inputIdentity(const uint8_t* data, size_t size)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < size; i++) {
        hash = (hash ^ data[i]) * UINT64_C(1099511628211);
    }
    return hash;
}

// Algorithm 1: SplitMix64, then descending Fisher-Yates with rejection sampling.
// Avoid std::shuffle/distributions: their output can differ across standard libraries.
class PermutationRandom {
public:
    explicit PermutationRandom(uint64_t state) : m_state(state) { }
    uint64_t next()
    {
        uint64_t value = (m_state += UINT64_C(0x9e3779b97f4a7c15));
        value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
        return value ^ (value >> 31);
    }
    size_t bounded(uint64_t bound)
    {
        const uint64_t threshold = (UINT64_C(0) - bound) % bound;
        uint64_t value;
        do {
            value = next();
        } while (value < threshold);
        return value % bound;
    }
private:
    uint64_t m_state;
};

class Reader {
public:
    Reader(const uint8_t* data, size_t size)
        : current(data), end(data + size) { }
    size_t remaining() const { return end - current; }
    void skip(size_t size)
    {
        require(size <= remaining(), "truncated data");
        current += size;
    }
    uint64_t number(size_t size)
    {
        require(size <= remaining(), "truncated data");
        auto value = readProtectedNumber(current, size);
        current += size;
        return value;
    }
    uint32_t uleb()
    {
        uint32_t value = 0;
        for (size_t i = 0; i < 5; i++) {
            uint8_t byte = number(1);
            require(i != 4 || !(byte & 0xf0), "invalid u32 LEB128");
            value |= static_cast<uint32_t>(byte & 0x7f) << (i * 7);
            if (!(byte & 0x80)) {
                return value;
            }
        }
        throw std::runtime_error("invalid u32 LEB128");
    }
    std::string string()
    {
        auto size = uleb();
        require(size <= remaining(), "truncated section name");
        std::string value(reinterpret_cast<const char*>(current), size);
        skip(size);
        return value;
    }
    const uint8_t* current;
    const uint8_t* end;
};

void number(std::vector<uint8_t>& output, uint64_t value, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        output.push_back(static_cast<uint8_t>(value >> (i * 8)));
    }
}

void uleb(std::vector<uint8_t>& output, uint32_t value)
{
    do {
        uint8_t byte = value & 0x7f;
        value >>= 7;
        output.push_back(value ? byte | 0x80 : byte);
    } while (value);
}

void appendSection(std::vector<uint8_t>& output, uint8_t id, const std::vector<uint8_t>& payload)
{
    require(payload.size() <= UINT32_MAX, "section is too large");
    output.push_back(id);
    uleb(output, payload.size());
    output.insert(output.end(), payload.begin(), payload.end());
}

struct Section {
    uint8_t id;
    const uint8_t* start;
    const uint8_t* data;
    size_t size;
    const uint8_t* end;
};

std::vector<Section> sections(const uint8_t* data, size_t size)
{
    require(size >= 8 && !memcmp(data, "\0asm\1\0\0\0", 8), "expected a core Wasm module");
    Reader reader(data + 8, size - 8);
    std::vector<Section> output;
    while (reader.remaining()) {
        Section section;
        section.start = reader.current;
        section.id = reader.number(1);
        section.size = reader.uleb();
        section.data = reader.current;
        reader.skip(section.size);
        section.end = reader.current;
        output.push_back(section);
    }
    return output;
}

uint64_t skeletonHash(const uint8_t* data, const std::vector<Section>& sections)
{
    // Association checksum, not a cryptographic integrity/authenticity mechanism.
    uint64_t hash = UINT64_C(14695981039346656037);
    auto update = [&hash](const uint8_t* begin, const uint8_t* end) {
        for (auto cursor = begin; cursor != end; cursor++) {
            hash = (hash ^ *cursor) * UINT64_C(1099511628211);
        }
    };
    update(data, data + 8);
    for (const auto& section : sections) {
        if (section.id) {
            update(section.start, section.end);
        }
    }
    return hash;
}

struct Body {
    const uint8_t* data;
    size_t size;
};

std::vector<Body> codeBodies(const std::vector<Section>& sections)
{
    std::vector<Body> output;
    for (const auto& section : sections) {
        if (section.id != 10) {
            continue;
        }
        Reader reader(section.data, section.size);
        uint32_t count = reader.uleb();
        require(count <= reader.remaining(), "invalid body count");
        for (uint32_t i = 0; i < count; i++) {
            auto size = reader.uleb();
            Body body = { reader.current, size };
            reader.skip(size);
            output.push_back(body);
        }
        require(!reader.remaining(), "trailing code section data");
    }
    return output;
}

template <typename Imports>
uint32_t importedFunctions(const Imports& imports)
{
    uint32_t count = 0;
    for (const auto& import : imports) {
        if (import->importType() == ImportType::Function) {
            count++;
        }
    }
    return count;
}

uint8_t typeCode(Value::Type type, bool floatingPoint = false)
{
    switch (type) {
    case Value::I32: return 0x7f;
    case Value::I64: return 0x7e;
    case Value::F32: if (floatingPoint) return 0x7d; break;
    case Value::F64: if (floatingPoint) return 0x7c; break;
    default: break;
    }
    throw std::runtime_error(floatingPoint ? "only i32/i64/f32/f64 types are supported" : "only i32/i64 function types and locals are supported; use --floating-point for f32/f64");
}

uint8_t typeWidth(Value::Type type)
{
    return type == Value::I32 || type == Value::F32 ? 4 : 8;
}

void checkFunctionType(ModuleFunction* function, bool extended = false, bool floatingPoint = false)
{
    auto type = function->functionType();
    require(extended || type->result().size() <= 1, "multiple return values are not supported in protected functions");
    for (auto value : type->param().types()) {
        typeCode(value, floatingPoint);
    }
    for (auto value : type->result().types()) {
        typeCode(value, floatingPoint);
    }
    for (auto value : function->locals()) {
        typeCode(value, floatingPoint);
    }
    require(!function->hasTryCatch(), "exception handlers are not supported in protected functions");
}

std::unique_ptr<ProtectedFunction> encodeFunction(Module* module, ModuleFunction* function, uint32_t index,
                                                uint64_t identity, const ProtectionOptions& options)
{
    const bool extended = options.extended || options.floatingPoint;
    checkFunctionType(function, extended, options.floatingPoint);
    require(!function->protectedFunction(), "input is already protected");
    std::unique_ptr<ProtectedFunction> output(new ProtectedFunction());
    output->functionIndex = index;
    output->formatVersion = options.floatingPoint ? 5 : (extended ? 4 : (options.version3 ? 3 : (options.version2 ? 2 : 1)));
    output->opcodeCount = options.floatingPoint ? protectedOpcodeCount : (extended ? protectedV4OpcodeCount : (options.version3 ? protectedV3OpcodeCount : protectedBaseOpcodeCount));
    output->fusionEnabled = options.fusion;
    output->frameSize = std::max<uint16_t>(8, function->requiredStackSize());
    output->resultCount = function->functionType()->result().size();
    output->resultWidth = output->resultCount ? typeWidth(function->functionType()->result().types()[0]) : 0;
    for (auto value : function->functionType()->result().types()) output->resultWidths.push_back(typeWidth(value));
    std::array<uint16_t, protectedOpcodeCount> encodeMap;
    for (size_t i = 0; i < output->opcodeCount; i++) {
        encodeMap[i] = i;
    }
    if (options.mode == ProtectionMode::Permuted) {
        PermutationRandom random(options.seed ^ identity
                                 ^ (static_cast<uint64_t>(index) * UINT64_C(0xd1b54a32d192ed03))
                                 ^ (options.floatingPoint ? UINT64_C(0x5747503500000001) : (extended ? UINT64_C(0x5747503400000001) : (options.version3 ? UINT64_C(0x5747503300000001) : UINT64_C(0x5747503200000001)))));
        for (size_t i = output->opcodeCount - 1; i > 0; i--) {
            std::swap(encodeMap[i], encodeMap[random.bounded(i + 1)]);
        }
        bool identityMap = true;
        for (size_t i = 0; i < output->opcodeCount; i++) {
            identityMap &= encodeMap[i] == i;
        }
        if (identityMap) {
            std::swap(encodeMap[0], encodeMap[1]);
        }
    }
    for (size_t i = 0; i < output->opcodeCount; i++) {
        output->opcodeMap[encodeMap[i]] = i;
    }
    std::vector<ProtectedInstruction> instructions;
    std::map<size_t, uint32_t> positions;
    std::vector<std::pair<size_t, int64_t>> branches;
    std::vector<std::pair<size_t, int64_t>> tableBranches;
    size_t offset = 0;
    while (offset < function->byteCodeSize()) {
        const auto* byteCode = reinterpret_cast<const ByteCode*>(function->byteCode() + offset);
        ProtectedInstruction instruction = { ProtectedOpcode::Unreachable, 0, 0, 0, 0 };
        positions[offset] = instructions.size();
        switch (byteCode->opcode()) {
#if !defined(NDEBUG)
        case ByteCode::NopOpcode:
            require(extended, "debug nop requires --extended (format v4)");
            // Debug-only no-ops have no effect. Keep their position mapped to the next record.
            offset += byteCode->getSize();
            continue;
#endif
        case ByteCode::Const32Opcode: {
            auto code = reinterpret_cast<const Const32*>(byteCode);
            instruction.opcode = ProtectedOpcode::Const32;
            instruction.destination = code->dstOffset();
            instruction.immediate = code->value();
            break;
        }
        case ByteCode::Const64Opcode: {
            auto code = reinterpret_cast<const Const64*>(byteCode);
            instruction.opcode = ProtectedOpcode::Const64;
            instruction.destination = code->dstOffset();
            instruction.immediate = code->value();
            break;
        }
        case ByteCode::MoveI32Opcode:
        case ByteCode::MoveI64Opcode: {
            auto code = reinterpret_cast<const ByteCodeOffset2*>(byteCode);
            instruction.opcode = byteCode->opcode() == ByteCode::MoveI32Opcode ? ProtectedOpcode::MoveI32 : ProtectedOpcode::MoveI64;
            instruction.source0 = code->stackOffset1();
            instruction.destination = code->stackOffset2();
            break;
        }
        case ByteCode::MoveF32Opcode:
        case ByteCode::MoveF64Opcode: {
            require(options.floatingPoint, "floating move requires --floating-point");
            const auto* code = reinterpret_cast<const MoveFloat*>(byteCode);
            instruction = { byteCode->opcode() == ByteCode::MoveF32Opcode ? ProtectedOpcode::MoveI32 : ProtectedOpcode::MoveI64,
                            code->srcOffset(), 0, code->dstOffset(), 0 };
            break;
        }
        case ByteCode::JumpOpcode:
            instruction.opcode = ProtectedOpcode::Jump;
            branches.push_back({ instructions.size(), static_cast<int64_t>(offset) + reinterpret_cast<const Jump*>(byteCode)->offset() });
            break;
        case ByteCode::JumpIfTrueOpcode:
        case ByteCode::JumpIfFalseOpcode: {
            auto code = reinterpret_cast<const ByteCodeOffsetValue*>(byteCode);
            instruction.opcode = byteCode->opcode() == ByteCode::JumpIfTrueOpcode ? ProtectedOpcode::JumpIfTrue : ProtectedOpcode::JumpIfFalse;
            instruction.source0 = code->stackOffset();
            branches.push_back({ instructions.size(), static_cast<int64_t>(offset) + code->int32Value() });
            break;
        }
        case ByteCode::EndOpcode: {
            auto code = reinterpret_cast<const End*>(byteCode);
            require(code->offsetsSize() == output->resultCount, "unsupported return layout");
            instruction.opcode = extended ? ProtectedOpcode::ReturnMany : ProtectedOpcode::Return;
            if (extended) {
                instruction.immediate = output->auxiliary.size();
                for (size_t i = 0; i < code->offsetsSize(); i++) output->auxiliary.push_back(code->resultOffsets()[i]);
            } else instruction.source0 = code->offsetsSize() ? code->resultOffsets()[0] : 0;
            break;
        }
        case ByteCode::UnreachableOpcode:
            break;
#define ENCODE_BINARY(name, ...) \
        case ByteCode::name##Opcode: { \
            auto code = reinterpret_cast<const BinaryOperation*>(byteCode); \
            instruction.opcode = ProtectedOpcode::name; \
            instruction.source0 = code->srcOffset()[0]; \
            instruction.source1 = code->srcOffset()[1]; \
            instruction.destination = code->dstOffset(); \
            break; \
        }
            FOR_EACH_PROTECTED_BINARY(ENCODE_BINARY)
            FOR_EACH_PROTECTED_INTEGER_BINARY(ENCODE_BINARY)
            FOR_EACH_PROTECTED_FLOAT_BINARY(ENCODE_BINARY)
#undef ENCODE_BINARY
#define ENCODE_UNARY(name, ...) \
        case ByteCode::name##Opcode: { \
            auto code = reinterpret_cast<const UnaryOperation*>(byteCode); \
            instruction.opcode = ProtectedOpcode::name; \
            instruction.source0 = code->srcOffset(); \
            instruction.destination = code->dstOffset(); \
            break; \
        }
            FOR_EACH_PROTECTED_UNARY(ENCODE_UNARY)
            FOR_EACH_PROTECTED_INTEGER_UNARY(ENCODE_UNARY)
            FOR_EACH_PROTECTED_FLOAT_UNARY(ENCODE_UNARY)
            FOR_EACH_PROTECTED_FLOAT_CONVERT(ENCODE_UNARY)
#undef ENCODE_UNARY
        case ByteCode::SelectOpcode: {
            const auto* code = reinterpret_cast<const Select*>(byteCode);
            require((options.floatingPoint || !code->isFloat()) && (code->valueSize() == 4 || code->valueSize() == 8), "floating select requires --floating-point");
            instruction = { code->valueSize() == 4 ? ProtectedOpcode::Select32 : ProtectedOpcode::Select64,
                            code->src0Offset(), code->src1Offset(), code->dstOffset(), code->condOffset() };
            break;
        }
        case ByteCode::BrTableOpcode: {
            const auto* code = reinterpret_cast<const BrTable*>(byteCode);
            instruction = { ProtectedOpcode::BrTable, code->condOffset(), 0, static_cast<uint32_t>(output->auxiliary.size()), code->tableSize() };
            require(code->tableSize() < payloadLimit / 4, "branch table is too large");
            for (size_t i = 0; i <= code->tableSize(); i++) {
                tableBranches.push_back({ output->auxiliary.size(), static_cast<int64_t>(offset) + (i == code->tableSize() ? code->defaultOffset() : code->jumpOffsets()[i]) });
                output->auxiliary.push_back(0);
            }
            break;
        }
#define ENCODE_LOAD(name, ...) \
        case ByteCode::name##Opcode: { const auto* code = reinterpret_cast<const MemoryLoad*>(byteCode); \
            instruction = { ProtectedOpcode::name, code->srcOffset(), 0, code->dstOffset(), code->offset() }; break; } \
        case ByteCode::name##MemIdxOpcode: { const auto* code = reinterpret_cast<const MemoryLoadMemIdx*>(byteCode); \
            instruction = { ProtectedOpcode::name, code->srcOffset(), code->memIndex(), code->dstOffset(), code->offset() }; break; }
            FOR_EACH_PROTECTED_LOAD(ENCODE_LOAD)
#undef ENCODE_LOAD
#define ENCODE_FLOAT_LOAD(name, ...) \
        case ByteCode::name##Opcode: { const auto* code = reinterpret_cast<const MemoryLoadFloat*>(byteCode); \
            instruction = { ProtectedOpcode::name, code->srcOffset(), 0, code->dstOffset(), code->offset() }; break; } \
        case ByteCode::name##MemIdxOpcode: { const auto* code = reinterpret_cast<const MemoryLoadFloatMemIdx*>(byteCode); \
            instruction = { ProtectedOpcode::name, code->srcOffset(), code->memIndex(), code->dstOffset(), code->offset() }; break; }
            FOR_EACH_PROTECTED_FLOAT_LOAD(ENCODE_FLOAT_LOAD)
#undef ENCODE_FLOAT_LOAD
        case ByteCode::Load32Opcode:
        case ByteCode::Load64Opcode: {
            const auto* code = reinterpret_cast<const ByteCodeOffset2*>(byteCode);
            instruction = { byteCode->opcode() == ByteCode::Load32Opcode ? ProtectedOpcode::I32Load : ProtectedOpcode::I64Load,
                            code->stackOffset1(), 0, code->stackOffset2(), 0 }; break;
        }
        case ByteCode::Store32Opcode:
        case ByteCode::Store64Opcode: {
            const auto* code = reinterpret_cast<const ByteCodeOffset2*>(byteCode);
            instruction = { byteCode->opcode() == ByteCode::Store32Opcode ? ProtectedOpcode::I32Store : ProtectedOpcode::I64Store,
                            code->stackOffset1(), code->stackOffset2(), 0, 0 }; break;
        }
#define ENCODE_STORE(name, ...) \
        case ByteCode::name##Opcode: { const auto* code = reinterpret_cast<const ByteCodeOffset2Value*>(byteCode); \
            instruction = { ProtectedOpcode::name, code->stackOffset1(), code->stackOffset2(), 0, code->uintValue() }; break; } \
        case ByteCode::name##MemIdxOpcode: { const auto* code = reinterpret_cast<const ByteCodeOffset2ValueMemIdx*>(byteCode); \
            instruction = { ProtectedOpcode::name, code->stackOffset1(), code->stackOffset2(), code->memIndex(), code->uintValue() }; break; }
            FOR_EACH_PROTECTED_STORE(ENCODE_STORE)
#undef ENCODE_STORE
#define ENCODE_GLOBAL(name, operand, frameField) \
        case ByteCode::name##Opcode: { const auto* code = reinterpret_cast<const name*>(byteCode); \
            instruction.opcode = ProtectedOpcode::name; instruction.frameField = code->operand(); instruction.immediate = code->index(); break; }
        ENCODE_GLOBAL(GlobalGet32, dstOffset, destination)
        ENCODE_GLOBAL(GlobalGet64, dstOffset, destination)
        ENCODE_GLOBAL(GlobalSet32, srcOffset, source0)
        ENCODE_GLOBAL(GlobalSet64, srcOffset, source0)
#undef ENCODE_GLOBAL
        case ByteCode::MemorySizeOpcode: {
            const auto* code = reinterpret_cast<const MemorySize*>(byteCode);
            instruction.opcode = ProtectedOpcode::MemorySize; instruction.destination = code->dstOffset(); instruction.immediate = code->memIndex(); break;
        }
        case ByteCode::MemoryGrowOpcode: {
            const auto* code = reinterpret_cast<const MemoryGrow*>(byteCode);
            instruction = { ProtectedOpcode::MemoryGrow, code->srcOffset(), 0, code->dstOffset(), code->memIndex() }; break;
        }
        case ByteCode::CallOpcode: {
            const auto* code = reinterpret_cast<const Call*>(byteCode);
            instruction.opcode = ProtectedOpcode::Call; instruction.immediate = code->index();
            instruction.destination = output->auxiliary.size();
            for (size_t i = 0; i < static_cast<size_t>(code->parameterOffsetsSize()) + code->resultOffsetsSize(); i++) output->auxiliary.push_back(code->stackOffsets()[i]);
            break;
        }
        case ByteCode::CallIndirectOpcode: {
            const auto* code = reinterpret_cast<const CallTable*>(byteCode);
            uint32_t typeIndex = 0;
            while (typeIndex < module->numberOfCompositeTypes() && module->compositeType(typeIndex) != code->functionType()) typeIndex++;
            require(typeIndex < module->numberOfCompositeTypes(), "indirect call type not found");
            instruction = { ProtectedOpcode::CallIndirect, code->calleeOffset(), code->tableIndex(), static_cast<uint32_t>(output->auxiliary.size()), typeIndex };
            for (size_t i = 0; i < static_cast<size_t>(code->parameterOffsetsSize()) + code->resultOffsetsSize(); i++) output->auxiliary.push_back(code->stackOffsets()[i]);
            break;
        }
        default:
            throw std::runtime_error("unsupported internal opcode " + std::to_string(byteCode->opcode()) + " at byte offset " + std::to_string(offset));
        }
        require(options.floatingPoint || static_cast<size_t>(instruction.opcode) < protectedV4OpcodeCount, "instruction requires --floating-point (format v5)");
        require(extended || static_cast<size_t>(instruction.opcode) < protectedV3OpcodeCount, "instruction requires --extended (format v4)");
        require(instructions.size() < payloadLimit / protectedInstructionSize, "too many protected instructions");
        instructions.push_back(instruction);
        const auto size = byteCode->getSize();
        require(size && size <= function->byteCodeSize() - offset, "invalid internal instruction boundary");
        offset += size;
    }
    for (const auto& branch : tableBranches) {
        require(branch.second >= 0 && positions.count(branch.second), "invalid branch table target");
        output->auxiliary[branch.first] = positions.at(branch.second);
    }
    for (const auto& branch : branches) {
        require(branch.second >= 0, "invalid internal branch target");
        auto target = positions.find(static_cast<size_t>(branch.second));
        require(target != positions.end(), "branch does not target an instruction");
        instructions[branch.first].immediate = target->second;
    }
    require(!instructions.empty(), "empty protected function");
    output->originalInstructionCount = instructions.size();
    if (options.fusion) {
        auto fused = fuseProtectedInstructions(instructions, &output->auxiliary);
        output->fusedInstructionCount = fused.fusedCount;
        output->skippedBranchEntryCount = fused.skippedBranchEntryCount;
        instructions.swap(fused.instructions);
    }
    for (const auto& instruction : instructions) {
        number(output->instructions, encodeMap[static_cast<size_t>(instruction.opcode)], 2);
        number(output->instructions, 0, 2);
        number(output->instructions, instruction.source0, 4);
        number(output->instructions, instruction.source1, 4);
        number(output->instructions, instruction.destination, 4);
        number(output->instructions, instruction.immediate, 8);
    }
    return output;
}

struct ProtectionContext {
    std::vector<ModuleFunction*> functions;
    std::vector<CompositeType*> types;
    std::vector<GlobalType*> globals;
    std::vector<MemoryType*> memories;
    std::vector<TableType*> tables;
};

ProtectionContext protectionContext(Module* module)
{
    ProtectionContext context;
    for (size_t i = 0; i < module->numberOfFunctions(); i++) context.functions.push_back(module->function(i));
    for (size_t i = 0; i < module->numberOfCompositeTypes(); i++) context.types.push_back(module->compositeType(i));
    for (size_t i = 0; i < module->numberOfGlobalTypes(); i++) context.globals.push_back(module->globalType(i));
    for (size_t i = 0; i < module->numberOfMemoryTypes(); i++) context.memories.push_back(module->memoryType(i));
    for (size_t i = 0; i < module->numberOfTableTypes(); i++) context.tables.push_back(module->tableType(i));
    return context;
}

void validateInstructions(ProtectedFunction& function, FunctionType* type, const ProtectionContext& context)
{
    const size_t count = function.instructions.size() / protectedInstructionSize;
    require(count, "empty protected instruction stream");
    uint32_t fusedCount = 0;
    auto slot = [&function](uint32_t offset, size_t width) {
        require(!(offset % width) && width <= function.frameSize && offset <= function.frameSize - width,
                "frame access is out of bounds or misaligned");
    };
    std::vector<bool> auxiliaryUsed(function.auxiliary.size(), false);
    auto auxiliary = [&function, &auxiliaryUsed](uint64_t offset, uint64_t size) {
        require(offset <= function.auxiliary.size() && size <= function.auxiliary.size() - offset, "auxiliary range is out of bounds");
        for (size_t i = 0; i < size; i++) {
            require(!auxiliaryUsed[offset + i], "overlapping auxiliary ranges");
            auxiliaryUsed[offset + i] = true;
        }
    };
    auto memory = [&context](uint64_t index) {
        require(index < context.memories.size(), "invalid protected memory index");
        require(!context.memories[index]->is64(), "memory64 requires a later protected format");
    };
    function.callOffsets.assign(std::max<size_t>(1, function.auxiliary.size()), 0);
    for (size_t i = 0; i < count; i++) {
        const auto* data = function.instructions.data() + i * protectedInstructionSize;
        const uint64_t encoded = readProtectedNumber(data, 2);
        require(encoded < function.opcodeCount, "unknown protected opcode");
        require(!readProtectedNumber(data + 2, 2), "nonzero instruction reserved field");
        const auto opcode = static_cast<ProtectedOpcode>(function.opcodeMap[encoded]);
        const uint32_t source0 = readProtectedNumber(data + 4, 4);
        const uint32_t source1 = readProtectedNumber(data + 8, 4);
        const uint32_t destination = readProtectedNumber(data + 12, 4);
        const uint64_t immediate = readProtectedNumber(data + 16, 8);
        const bool terminal = opcode == ProtectedOpcode::Return || opcode == ProtectedOpcode::ReturnMany || opcode == ProtectedOpcode::BrTable || opcode == ProtectedOpcode::Unreachable || opcode == ProtectedOpcode::Jump;
        require(terminal || i + 1 < count, "instruction falls through past the stream");
        switch (opcode) {
        case ProtectedOpcode::Const32:
            slot(destination, 4);
            require(immediate <= UINT32_MAX && !source0 && !source1, "invalid const32 operands");
            break;
        case ProtectedOpcode::Const64:
            slot(destination, 8);
            require(!source0 && !source1, "invalid const64 operands");
            break;
        case ProtectedOpcode::MoveI32:
        case ProtectedOpcode::MoveI64:
            slot(source0, opcode == ProtectedOpcode::MoveI32 ? 4 : 8);
            slot(destination, opcode == ProtectedOpcode::MoveI32 ? 4 : 8);
            require(!source1 && !immediate, "invalid move operands");
            break;
        case ProtectedOpcode::Jump:
        case ProtectedOpcode::JumpIfTrue:
        case ProtectedOpcode::JumpIfFalse:
            require(immediate < count, "branch target is out of bounds");
            require(!source1 && !destination, "invalid branch operands");
            if (opcode == ProtectedOpcode::Jump) {
                require(!source0, "invalid jump operand");
            } else {
                slot(source0, 4);
            }
            break;
        case ProtectedOpcode::Return:
            require(function.resultCount <= 1, "legacy return cannot return multiple values");
            require(!source1 && !destination && !immediate, "invalid return operands");
            if (function.resultCount) {
                slot(source0, function.resultWidth);
            } else {
                require(!source0, "unexpected return value");
            }
            break;
        case ProtectedOpcode::ReturnMany:
            require(function.formatVersion >= 4 && !source0 && !source1 && !destination, "invalid multiple return operands");
            auxiliary(immediate, function.resultCount);
            for (size_t j = 0; j < function.resultCount; j++) slot(function.auxiliary[immediate + j], function.resultWidths[j]);
            break;
        case ProtectedOpcode::Unreachable:
            require(!source0 && !source1 && !destination && !immediate, "invalid unreachable operands");
            break;
        case ProtectedOpcode::I32AddMoveI32:
            require(function.fusionEnabled, "fused opcode requires fusion mode");
            slot(source0, 4);
            slot(source1, 4);
            slot(destination, 4);
            require(immediate <= UINT32_MAX, "invalid fused move immediate");
            slot(static_cast<uint32_t>(immediate), 4);
            fusedCount++;
            break;
        case ProtectedOpcode::I64ExtendI32UAddI64:
            require(function.fusionEnabled, "fused opcode requires fusion mode");
            slot(source0, 4);
            slot(source1, 8);
            slot(destination, 8);
            require(!(immediate >> 33), "invalid fused extend immediate");
            slot(static_cast<uint32_t>(immediate), 8);
            fusedCount++;
            break;
#define VALIDATE_BINARY(name, inputType, outputType, ...) \
        case ProtectedOpcode::name: \
            slot(source0, sizeof(inputType)); \
            slot(source1, sizeof(inputType)); \
            slot(destination, sizeof(outputType)); \
            require(!immediate, "invalid binary immediate"); \
            break;
            FOR_EACH_PROTECTED_BINARY(VALIDATE_BINARY)
            FOR_EACH_PROTECTED_FLOAT_BINARY(VALIDATE_BINARY)
#undef VALIDATE_BINARY
#define VALIDATE_UNARY(name, inputType, outputType, ...) \
        case ProtectedOpcode::name: \
            slot(source0, sizeof(inputType)); \
            slot(destination, sizeof(outputType)); \
            require(!source1 && !immediate, "invalid unary operands"); \
            break;
            FOR_EACH_PROTECTED_UNARY(VALIDATE_UNARY)
            FOR_EACH_PROTECTED_FLOAT_UNARY(VALIDATE_UNARY)
            FOR_EACH_PROTECTED_FLOAT_CONVERT(VALIDATE_UNARY)
#undef VALIDATE_UNARY
#define VALIDATE_EXTENDED_BINARY(name, inputType, ...) \
        case ProtectedOpcode::name: slot(source0, sizeof(inputType)); slot(source1, sizeof(inputType)); slot(destination, sizeof(inputType)); \
            require(!immediate, "invalid integer binary immediate"); break;
            FOR_EACH_PROTECTED_INTEGER_BINARY(VALIDATE_EXTENDED_BINARY)
#undef VALIDATE_EXTENDED_BINARY
#define VALIDATE_EXTENDED_UNARY(name, inputType, ...) \
        case ProtectedOpcode::name: slot(source0, sizeof(inputType)); slot(destination, sizeof(inputType)); \
            require(!source1 && !immediate, "invalid integer unary operands"); break;
            FOR_EACH_PROTECTED_INTEGER_UNARY(VALIDATE_EXTENDED_UNARY)
#undef VALIDATE_EXTENDED_UNARY
#define VALIDATE_LOAD(name, readType, writeType) \
        case ProtectedOpcode::name: slot(source0, 4); slot(destination, sizeof(writeType)); memory(source1); \
            require(immediate <= UINT32_MAX, "invalid load offset"); break;
            FOR_EACH_PROTECTED_LOAD(VALIDATE_LOAD)
            FOR_EACH_PROTECTED_FLOAT_LOAD(VALIDATE_LOAD)
#undef VALIDATE_LOAD
#define VALIDATE_STORE(name, readType, writeType) \
        case ProtectedOpcode::name: slot(source0, 4); slot(source1, sizeof(readType)); memory(destination); \
            require(immediate <= UINT32_MAX, "invalid store offset"); break;
            FOR_EACH_PROTECTED_STORE(VALIDATE_STORE)
#undef VALIDATE_STORE
        case ProtectedOpcode::Select32:
        case ProtectedOpcode::Select64: {
            const size_t width = opcode == ProtectedOpcode::Select32 ? 4 : 8;
            slot(source0, width); slot(source1, width); slot(destination, width);
            require(immediate <= UINT32_MAX, "invalid select condition"); slot(immediate, 4); break;
        }
        case ProtectedOpcode::BrTable:
            slot(source0, 4); require(!source1 && immediate < UINT32_MAX, "invalid branch table operands");
            auxiliary(destination, immediate + 1);
            for (size_t j = 0; j <= immediate; j++) require(function.auxiliary[destination + j] < count, "branch table target is out of bounds");
            break;
        case ProtectedOpcode::GlobalGet32:
        case ProtectedOpcode::GlobalGet64:
        case ProtectedOpcode::GlobalSet32:
        case ProtectedOpcode::GlobalSet64: {
            const bool get = opcode == ProtectedOpcode::GlobalGet32 || opcode == ProtectedOpcode::GlobalGet64;
            const bool word32 = opcode == ProtectedOpcode::GlobalGet32 || opcode == ProtectedOpcode::GlobalSet32;
            require(immediate < context.globals.size(), "invalid protected global index");
            auto global = context.globals[immediate];
            const auto valueType = global->type().type();
            require(valueType == (word32 ? Value::I32 : Value::I64)
                        || (function.formatVersion >= 5 && valueType == (word32 ? Value::F32 : Value::F64)), "protected global type mismatch");
            require(get || global->isMutable(), "protected global is immutable");
            require(!source1 && (get ? !source0 : !destination), "invalid global operands");
            slot(get ? destination : source0, word32 ? 4 : 8); break;
        }
        case ProtectedOpcode::MemorySize:
        case ProtectedOpcode::MemoryGrow:
            memory(immediate); require(!source1, "invalid memory operands"); slot(destination, 4);
            if (opcode == ProtectedOpcode::MemoryGrow) {
                slot(source0, 4);
            } else {
                require(!source0, "invalid memory.size operands");
            }
            break;
        case ProtectedOpcode::Call:
        case ProtectedOpcode::CallIndirect: {
            FunctionType* targetType;
            if (opcode == ProtectedOpcode::Call) {
                require(immediate < context.functions.size(), "invalid protected call index");
                require(!source0 && !source1, "invalid call operands");
                targetType = context.functions[immediate]->functionType();
            } else {
                require(source1 < context.tables.size(), "invalid protected table index");
                const auto tableType = context.tables[source1]->type().type();
                require(!context.tables[source1]->is64() && (tableType == Value::FuncRef || tableType == Value::NullFuncRef), "call_indirect requires a table32 funcref table");
                require(immediate < context.types.size() && context.types[immediate]->kind() == ObjectType::FunctionKind, "invalid protected call type index");
                slot(source0, 4); targetType = context.types[immediate]->asFunction();
            }
            const size_t params = targetType->param().size(), results = targetType->result().size();
            require(params <= UINT16_MAX && results <= UINT16_MAX, "protected call signature is too large");
            auxiliary(destination, params + results);
            size_t j = 0;
            for (auto value : targetType->param().types()) {
                typeCode(value, function.formatVersion >= 5);
                const uint32_t offset = function.auxiliary[destination + j];
                // f32/i32 constants can be packed at 4-byte offsets. The call ABI reads a full word.
                slot(offset, function.formatVersion >= 5 ? typeWidth(value) : 8);
                require(offset <= function.frameSize - 8u, "call frame access is out of bounds");
                function.callOffsets[destination + j++] = offset;
            }
            for (auto value : targetType->result().types()) {
                typeCode(value, function.formatVersion >= 5); const uint32_t offset = function.auxiliary[destination + j]; slot(offset, 8);
                function.callOffsets[destination + j++] = offset;
            }
            break;
        }
        default:
            throw std::runtime_error("unknown protected opcode");
        }
    }
    require(fusedCount == function.fusedInstructionCount, "fused instruction count mismatch");
    require(static_cast<uint64_t>(function.originalInstructionCount) == count + fusedCount, "original instruction count mismatch");
    require(function.skippedBranchEntryCount <= function.originalInstructionCount, "invalid skipped fusion count");
    require(function.fusionEnabled || !function.skippedBranchEntryCount, "fusion-off record has skipped candidates");
    require(function.resultCount == type->result().size(), "return type mismatch");
    for (bool used : auxiliaryUsed) require(used, "unreferenced auxiliary entry");
}
} // namespace

std::string packProtectedModule(Module* module, const uint8_t* data, size_t size,
                                const std::vector<uint32_t>& functions, const ProtectionOptions& options,
                                std::vector<uint8_t>& output)
{
    try {
        const bool extended = options.extended || options.floatingPoint;
        require(sizeof(size_t) == 8, "protected modules require a 64-bit Walrus build");
        require(options.mode == ProtectionMode::Identity || options.mode == ProtectionMode::Permuted, "invalid protection mode");
        require(extended || options.version2 || options.version3 || options.mode == ProtectionMode::Identity, "permutation requires format v2 or later");
        require(!options.fusion || ((extended || options.version3) && options.mode == ProtectionMode::Permuted), "fusion requires format v3 or later and permuted mode");
        require(options.mode == ProtectionMode::Permuted || !options.seed, "identity mode does not use a seed");
        require(!functions.empty(), "no protection targets supplied");
        const auto inputSections = sections(data, size);
        auto context = protectionContext(module);
        for (const auto& section : inputSections) {
            require(section.id != 8 || extended, "modules with a start function are not supported in protected format");
            if (!section.id) {
                Reader reader(section.data, section.size);
                require(!isProtectionSection(reader.string()), "input is already protected");
            }
        }
        const auto bodies = codeBodies(inputSections);
        const uint32_t imported = importedFunctions(module->imports());
        // Walrus can append synthetic initializer functions after declared functions.
        require(bodies.size() + imported <= module->numberOfFunctions(), "function/code count mismatch");
        context.functions.resize(bodies.size() + imported);
        std::map<uint32_t, std::unique_ptr<ProtectedFunction>> protectedFunctions;
        const uint64_t identity = inputIdentity(data, size);
        for (auto index : functions) {
            require(index >= imported && index < imported + bodies.size(), "protection target is not a defined function");
            require(!protectedFunctions.count(index), "duplicate protection target");
            try {
                auto function = encodeFunction(module, module->function(index), index, identity, options);
                validateInstructions(*function, module->function(index)->functionType(), context);
                protectedFunctions.emplace(index, std::move(function));
            } catch (const std::runtime_error& error) {
                throw std::runtime_error("function " + std::to_string(index) + ": " + error.what());
            }
        }
        std::vector<uint8_t> skeleton(data, data + 8);
        for (const auto& section : inputSections) {
            // Drop custom/debug/name sections: they can carry original source/code.
            if (!section.id) {
                continue;
            }
            if (section.id != 10) {
                skeleton.insert(skeleton.end(), section.start, section.end);
                continue;
            }
            std::vector<uint8_t> code;
            uleb(code, bodies.size());
            for (size_t i = 0; i < bodies.size(); i++) {
                const bool protect = protectedFunctions.count(imported + i);
                const auto* body = protect ? stubBody : bodies[i].data;
                const size_t bodySize = protect ? sizeof(stubBody) : bodies[i].size;
                uleb(code, bodySize);
                code.insert(code.end(), body, body + bodySize);
            }
            appendSection(skeleton, 10, code);
        }
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), { 'W', 'G', 'P', '1' });
        number(payload, options.floatingPoint ? 5 : (extended ? 4 : (options.version3 ? 3 : (options.version2 ? 2 : 1))), 4);
        number(payload, 8, 4);
        number(payload, skeletonHash(skeleton.data(), sections(skeleton.data(), skeleton.size())), 8);
        number(payload, protectedFunctions.size(), 4);
        if (options.version2 || options.version3 || extended) {
            number(payload, static_cast<uint32_t>(options.mode), 4);
            number(payload, 1, 4); // permutation algorithm version, shared by both modes
            number(payload, options.seed, 8);
            number(payload, identity, 8);
        }
        if (options.version3 || extended) {
            number(payload, options.fusion ? 1 : 0, 4);
            number(payload, 1, 4); // two-instruction fusion algorithm version
        }
        for (const auto& entry : protectedFunctions) {
            auto type = module->function(entry.first)->functionType();
            const auto& function = *entry.second;
            number(payload, entry.first, 4);
            number(payload, function.frameSize, 4);
            number(payload, type->param().size(), 4);
            number(payload, function.resultCount, 4);
            number(payload, function.instructions.size() / protectedInstructionSize, 4);
            number(payload, function.opcodeCount, 4);
            if (options.version3 || extended) {
                number(payload, function.originalInstructionCount, 4);
                number(payload, function.fusedInstructionCount, 4);
                number(payload, function.skippedBranchEntryCount, 4);
            }
            if (extended) number(payload, function.auxiliary.size(), 4);
            for (auto value : type->param().types()) {
                number(payload, typeCode(value, options.floatingPoint), 1);
            }
            for (auto value : type->result().types()) {
                number(payload, typeCode(value, options.floatingPoint), 1);
            }
            for (size_t i = 0; i < function.opcodeCount; i++) {
                number(payload, function.opcodeMap[i], 2);
            }
            require(function.instructions.size() <= payloadLimit - std::min(payload.size(), payloadLimit), "protected payload is too large");
            payload.insert(payload.end(), function.instructions.begin(), function.instructions.end());
            for (auto value : function.auxiliary) number(payload, value, 4);
            require(payload.size() <= payloadLimit, "protected payload is too large");
        }
        std::vector<uint8_t> custom;
        const char* name = options.version2 || options.version3 || extended ? commonSectionName : sectionName;
        const size_t nameSize = strlen(name);
        uleb(custom, nameSize);
        custom.insert(custom.end(), name, name + nameSize);
        custom.insert(custom.end(), payload.begin(), payload.end());
        appendSection(skeleton, 0, custom);
        output.swap(skeleton);
        return std::string();
    } catch (const std::runtime_error& error) {
        return std::string(options.fusion ? "G3: " : (options.mode == ProtectionMode::Permuted ? "G2: " : "G1: ")) + error.what();
    }
}

std::string loadProtectedFunctions(WASMParsingResult& result, const uint8_t* data, size_t size, bool useJIT)
{
    try {
        const auto inputSections = sections(data, size);
        const uint8_t* payload = nullptr;
        size_t payloadSize = 0;
        bool commonFormat = false;
        for (const auto& section : inputSections) {
            if (!section.id) {
                Reader reader(section.data, section.size);
                const auto name = reader.string();
                if (isProtectionSection(name)) {
                    require(!payload, "duplicate protection section");
                    payload = reader.current;
                    payloadSize = reader.remaining();
                    commonFormat = name == commonSectionName;
                }
            }
        }
        if (!payload) {
            return std::string();
        }
        require(sizeof(size_t) == 8, "protected modules require a 64-bit Walrus build");
        require(!useJIT, "protected modules require interpreter execution; disable --jit");
        require(payloadSize <= payloadLimit, "protected payload is too large");
        Reader reader(payload, payloadSize);
        require(reader.number(4) == UINT32_C(0x31504757), "invalid protection magic");
        const auto version = reader.number(4);
        require(commonFormat ? (version >= 2 && version <= 5) : version == 1, "unsupported protection format version");
        require(!result.m_seenStartAttribute || version >= 4, "modules with a start function are not supported in protected format");
        require(reader.number(4) == 8, "incompatible frame ABI");
        require(reader.number(8) == skeletonHash(data, inputSections), "payload/skeleton checksum mismatch");
        const auto count = reader.number(4);
        ProtectionMode mode = ProtectionMode::Identity;
        if (version >= 2) {
            const auto rawMode = reader.number(4);
            require(rawMode <= static_cast<uint32_t>(ProtectionMode::Permuted), "invalid protection mode");
            mode = static_cast<ProtectionMode>(rawMode);
            require(reader.number(4) == 1, "unsupported permutation algorithm version");
            const auto seed = reader.number(8);
            require(mode == ProtectionMode::Permuted || !seed, "identity mode does not use a seed");
            reader.number(8); // original input identity is reproducibility metadata, not authentication
        }
        bool fusion = false;
        if (version >= 3) {
            const auto enabled = reader.number(4);
            require(enabled <= 1, "invalid fusion mode");
            fusion = enabled;
            require(reader.number(4) == 1, "unsupported fusion algorithm version");
            require(!fusion || mode == ProtectionMode::Permuted, "fusion requires permuted mode");
        }
        ProtectionContext context;
        context.functions.assign(result.m_functions.begin(), result.m_functions.end());
        context.types.assign(result.m_compositeTypes.begin(), result.m_compositeTypes.end());
        context.globals.assign(result.m_globalTypes.begin(), result.m_globalTypes.end());
        context.memories.assign(result.m_memoryTypes.begin(), result.m_memoryTypes.end());
        context.tables.assign(result.m_tableTypes.begin(), result.m_tableTypes.end());
        const uint32_t imported = importedFunctions(result.m_imports);
        const auto bodies = codeBodies(inputSections);
        require(count && count <= bodies.size(), "invalid protected function count");
        require(bodies.size() + imported <= result.m_functions.size(), "function/code count mismatch");
        context.functions.resize(bodies.size() + imported);
        std::map<uint32_t, std::unique_ptr<ProtectedFunction>> functions;
        for (size_t i = 0; i < count; i++) {
            const uint32_t index = reader.number(4);
            const uint64_t frameSize = reader.number(4);
            const uint64_t paramCount = reader.number(4);
            const uint64_t resultCount = reader.number(4);
            const uint64_t instructionCount = reader.number(4);
            const uint64_t mapCount = reader.number(4);
            const uint64_t originalCount = version >= 3 ? reader.number(4) : instructionCount;
            const uint64_t fusedCount = version >= 3 ? reader.number(4) : 0;
            const uint64_t skippedCount = version >= 3 ? reader.number(4) : 0;
            const uint64_t auxiliaryCount = version >= 4 ? reader.number(4) : 0;
            require(index >= imported && index < imported + bodies.size(), "invalid protected function index");
            require(!functions.count(index), "duplicate protected function index");
            const auto& body = bodies[index - imported];
            require(body.size == sizeof(stubBody) && !memcmp(body.data, stubBody, sizeof(stubBody)), "protected function must have the canonical stub body");
            auto* moduleFunction = result.m_functions[index];
            checkFunctionType(moduleFunction, version >= 4, version >= 5);
            auto type = moduleFunction->functionType();
            require(frameSize >= 8 && frameSize <= UINT16_MAX && !(frameSize % 8)
                        && frameSize >= type->paramStackSize() && frameSize >= type->resultStackSize(), "invalid protected frame size");
            require(paramCount == type->param().size() && resultCount == type->result().size(), "protected signature count mismatch");
            require(mapCount == (version == 5 ? protectedOpcodeCount : (version == 4 ? protectedV4OpcodeCount : (version == 3 ? protectedV3OpcodeCount : protectedBaseOpcodeCount))), "invalid opcode mapping size");
            for (auto value : type->param().types()) {
                require(reader.number(1) == typeCode(value, version >= 5), "protected parameter type mismatch");
            }
            for (auto value : type->result().types()) {
                require(reader.number(1) == typeCode(value, version >= 5), "protected return type mismatch");
            }
            std::unique_ptr<ProtectedFunction> function(new ProtectedFunction());
            function->functionIndex = index;
            function->opcodeCount = mapCount;
            function->formatVersion = version;
            function->fusionEnabled = fusion;
            function->originalInstructionCount = originalCount;
            function->fusedInstructionCount = fusedCount;
            function->skippedBranchEntryCount = skippedCount;
            function->frameSize = frameSize;
            function->resultCount = resultCount;
            function->resultWidth = resultCount ? typeWidth(type->result().types()[0]) : 0;
            for (auto value : type->result().types()) function->resultWidths.push_back(typeWidth(value));
            std::array<bool, protectedOpcodeCount> seen = {};
            bool identityMap = true;
            for (size_t j = 0; j < mapCount; j++) {
                const auto opcode = reader.number(2);
                require(opcode < mapCount, "opcode mapping is out of range");
                require(!seen[opcode], "duplicate opcode mapping entry");
                seen[opcode] = true;
                identityMap &= opcode == j;
                require(mode != ProtectionMode::Identity || opcode == j, "G1 requires an identity opcode mapping");
                function->opcodeMap[j] = opcode;
            }
            require(mode != ProtectionMode::Permuted || !identityMap, "permuted mode requires a non-identity opcode mapping");
            require(instructionCount && instructionCount <= reader.remaining() / protectedInstructionSize, "invalid protected instruction count");
            const size_t bytes = instructionCount * protectedInstructionSize;
            function->instructions.assign(reader.current, reader.current + bytes);
            reader.skip(bytes);
            require(auxiliaryCount <= reader.remaining() / 4, "invalid protected auxiliary count");
            for (size_t j = 0; j < auxiliaryCount; j++) function->auxiliary.push_back(reader.number(4));
            validateInstructions(*function, type, context);
            functions.emplace(index, std::move(function));
        }
        require(!reader.remaining(), "trailing protected payload data");
        // Attach only after every record has passed validation.
        for (auto& entry : functions) {
            result.m_functions[entry.first]->setProtectedFunction(std::move(entry.second));
        }
        return std::string();
    } catch (const std::runtime_error& error) {
        return std::string("protected: ") + error.what();
    }
}
} // namespace Walrus
