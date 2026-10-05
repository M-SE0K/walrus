/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#include "Walrus.h"
#include "parser/ProtectedModule.h"
#include "parser/WASMParser.h"
#include "interpreter/ByteCode.h"
#include "interpreter/ProtectedByteCode.h"
#include <map>
#include <stdexcept>

namespace Walrus {
namespace {
const char sectionName[] = "walrus.protected.g1";
const uint8_t stubBody[] = { 0, 0, 0x0b }; // no locals; unreachable; end
const size_t payloadLimit = 64 * 1024 * 1024;

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

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

uint8_t typeCode(Value::Type type)
{
    require(type == Value::I32 || type == Value::I64, "only i32/i64 function types and locals are supported");
    return type == Value::I32 ? 0x7f : 0x7e;
}

void checkFunctionType(ModuleFunction* function)
{
    auto type = function->functionType();
    require(type->result().size() <= 1, "multiple return values are not supported in G1 v1");
    for (auto value : type->param().types()) {
        typeCode(value);
    }
    for (auto value : type->result().types()) {
        typeCode(value);
    }
    for (auto value : function->locals()) {
        typeCode(value);
    }
    require(!function->hasTryCatch(), "exception handlers are not supported in protected functions");
}

struct Instruction {
    ProtectedOpcode opcode;
    uint32_t source0;
    uint32_t source1;
    uint32_t destination;
    uint64_t immediate;
};

std::unique_ptr<ProtectedFunction> encodeFunction(ModuleFunction* function)
{
    checkFunctionType(function);
    require(!function->protectedFunction(), "input is already protected");
    std::unique_ptr<ProtectedFunction> output(new ProtectedFunction());
    output->frameSize = std::max<uint16_t>(8, function->requiredStackSize());
    output->resultCount = function->functionType()->result().size();
    output->resultWidth = output->resultCount ? (typeCode(function->functionType()->result().types()[0]) == 0x7f ? 4 : 8) : 0;
    for (size_t i = 0; i < protectedOpcodeCount; i++) {
        output->opcodeMap[i] = i;
    }
    std::vector<Instruction> instructions;
    std::map<size_t, uint32_t> positions;
    std::vector<std::pair<size_t, int64_t>> branches;
    size_t offset = 0;
    while (offset < function->byteCodeSize()) {
        const auto* byteCode = reinterpret_cast<const ByteCode*>(function->byteCode() + offset);
        Instruction instruction = { ProtectedOpcode::Unreachable, 0, 0, 0, 0 };
        positions[offset] = instructions.size();
        switch (byteCode->opcode()) {
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
            instruction.opcode = ProtectedOpcode::Return;
            instruction.source0 = code->offsetsSize() ? code->resultOffsets()[0] : 0;
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
#undef ENCODE_UNARY
        default:
            throw std::runtime_error("unsupported internal opcode " + std::to_string(byteCode->opcode()) + " at byte offset " + std::to_string(offset));
        }
        require(instructions.size() < payloadLimit / protectedInstructionSize, "too many protected instructions");
        instructions.push_back(instruction);
        const auto size = byteCode->getSize();
        require(size && size <= function->byteCodeSize() - offset, "invalid internal instruction boundary");
        offset += size;
    }
    for (const auto& branch : branches) {
        require(branch.second >= 0, "invalid internal branch target");
        auto target = positions.find(static_cast<size_t>(branch.second));
        require(target != positions.end(), "branch does not target an instruction");
        instructions[branch.first].immediate = target->second;
    }
    require(!instructions.empty(), "empty protected function");
    for (const auto& instruction : instructions) {
        number(output->instructions, static_cast<uint16_t>(instruction.opcode), 2);
        number(output->instructions, 0, 2);
        number(output->instructions, instruction.source0, 4);
        number(output->instructions, instruction.source1, 4);
        number(output->instructions, instruction.destination, 4);
        number(output->instructions, instruction.immediate, 8);
    }
    return output;
}

void validateInstructions(const ProtectedFunction& function, FunctionType* type)
{
    const size_t count = function.instructions.size() / protectedInstructionSize;
    require(count, "empty protected instruction stream");
    auto slot = [&function](uint32_t offset, size_t width) {
        require(!(offset % width) && width <= function.frameSize && offset <= function.frameSize - width,
                "frame access is out of bounds or misaligned");
    };
    for (size_t i = 0; i < count; i++) {
        const auto* data = function.instructions.data() + i * protectedInstructionSize;
        const uint64_t encoded = readProtectedNumber(data, 2);
        require(encoded < protectedOpcodeCount, "unknown protected opcode");
        require(!readProtectedNumber(data + 2, 2), "nonzero instruction reserved field");
        const auto opcode = static_cast<ProtectedOpcode>(function.opcodeMap[encoded]);
        const uint32_t source0 = readProtectedNumber(data + 4, 4);
        const uint32_t source1 = readProtectedNumber(data + 8, 4);
        const uint32_t destination = readProtectedNumber(data + 12, 4);
        const uint64_t immediate = readProtectedNumber(data + 16, 8);
        const bool terminal = opcode == ProtectedOpcode::Return || opcode == ProtectedOpcode::Unreachable || opcode == ProtectedOpcode::Jump;
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
            require(!source1 && !destination && !immediate, "invalid return operands");
            if (function.resultCount) {
                slot(source0, function.resultWidth);
            } else {
                require(!source0, "unexpected return value");
            }
            break;
        case ProtectedOpcode::Unreachable:
            require(!source0 && !source1 && !destination && !immediate, "invalid unreachable operands");
            break;
#define VALIDATE_BINARY(name, inputType, outputType, ...) \
        case ProtectedOpcode::name: \
            slot(source0, sizeof(inputType)); \
            slot(source1, sizeof(inputType)); \
            slot(destination, sizeof(outputType)); \
            require(!immediate, "invalid binary immediate"); \
            break;
            FOR_EACH_PROTECTED_BINARY(VALIDATE_BINARY)
#undef VALIDATE_BINARY
#define VALIDATE_UNARY(name, inputType, outputType, ...) \
        case ProtectedOpcode::name: \
            slot(source0, sizeof(inputType)); \
            slot(destination, sizeof(outputType)); \
            require(!source1 && !immediate, "invalid unary operands"); \
            break;
            FOR_EACH_PROTECTED_UNARY(VALIDATE_UNARY)
#undef VALIDATE_UNARY
        default:
            throw std::runtime_error("unknown protected opcode");
        }
    }
    require(function.resultCount == type->result().size(), "return type mismatch");
}
} // namespace

std::string packProtectedModule(Module* module, const uint8_t* data, size_t size,
                                const std::vector<uint32_t>& functions, std::vector<uint8_t>& output)
{
    try {
        require(sizeof(size_t) == 8, "G1 v1 requires a 64-bit Walrus build");
        require(!functions.empty(), "no protection targets supplied");
        const auto inputSections = sections(data, size);
        for (const auto& section : inputSections) {
            require(section.id != 8, "modules with a start function are not supported in G1 v1");
            if (!section.id) {
                Reader reader(section.data, section.size);
                require(reader.string() != sectionName, "input is already protected");
            }
        }
        const auto bodies = codeBodies(inputSections);
        const uint32_t imported = importedFunctions(module->imports());
        // Walrus can append synthetic initializer functions after declared functions.
        require(bodies.size() + imported <= module->numberOfFunctions(), "function/code count mismatch");
        std::map<uint32_t, std::unique_ptr<ProtectedFunction>> protectedFunctions;
        for (auto index : functions) {
            require(index >= imported && index < imported + bodies.size(), "protection target is not a defined function");
            require(!protectedFunctions.count(index), "duplicate protection target");
            try {
                auto function = encodeFunction(module->function(index));
                validateInstructions(*function, module->function(index)->functionType());
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
        number(payload, 1, 4);
        number(payload, 8, 4);
        number(payload, skeletonHash(skeleton.data(), sections(skeleton.data(), skeleton.size())), 8);
        number(payload, protectedFunctions.size(), 4);
        for (const auto& entry : protectedFunctions) {
            auto type = module->function(entry.first)->functionType();
            const auto& function = *entry.second;
            number(payload, entry.first, 4);
            number(payload, function.frameSize, 4);
            number(payload, type->param().size(), 4);
            number(payload, function.resultCount, 4);
            number(payload, function.instructions.size() / protectedInstructionSize, 4);
            number(payload, protectedOpcodeCount, 4);
            for (auto value : type->param().types()) {
                number(payload, typeCode(value), 1);
            }
            for (auto value : type->result().types()) {
                number(payload, typeCode(value), 1);
            }
            for (auto value : function.opcodeMap) {
                number(payload, value, 2);
            }
            require(function.instructions.size() <= payloadLimit - std::min(payload.size(), payloadLimit), "protected payload is too large");
            payload.insert(payload.end(), function.instructions.begin(), function.instructions.end());
        }
        std::vector<uint8_t> custom;
        uleb(custom, sizeof(sectionName) - 1);
        custom.insert(custom.end(), sectionName, sectionName + sizeof(sectionName) - 1);
        custom.insert(custom.end(), payload.begin(), payload.end());
        appendSection(skeleton, 0, custom);
        output.swap(skeleton);
        return std::string();
    } catch (const std::runtime_error& error) {
        return std::string("G1: ") + error.what();
    }
}

std::string loadProtectedFunctions(WASMParsingResult& result, const uint8_t* data, size_t size, bool useJIT)
{
    try {
        const auto inputSections = sections(data, size);
        const uint8_t* payload = nullptr;
        size_t payloadSize = 0;
        for (const auto& section : inputSections) {
            if (!section.id) {
                Reader reader(section.data, section.size);
                if (reader.string() == sectionName) {
                    require(!payload, "duplicate protection section");
                    payload = reader.current;
                    payloadSize = reader.remaining();
                }
            }
        }
        if (!payload) {
            return std::string();
        }
        require(sizeof(size_t) == 8, "G1 v1 requires a 64-bit Walrus build");
        require(!useJIT, "G1 v1 requires interpreter execution; disable --jit");
        require(!result.m_seenStartAttribute, "modules with a start function are not supported in G1 v1");
        require(payloadSize <= payloadLimit, "protected payload is too large");
        Reader reader(payload, payloadSize);
        require(reader.number(4) == UINT32_C(0x31504757), "invalid protection magic");
        require(reader.number(4) == 1, "unsupported protection format version");
        require(reader.number(4) == 8, "incompatible frame ABI");
        require(reader.number(8) == skeletonHash(data, inputSections), "payload/skeleton checksum mismatch");
        const auto count = reader.number(4);
        const uint32_t imported = importedFunctions(result.m_imports);
        const auto bodies = codeBodies(inputSections);
        require(count && count <= bodies.size(), "invalid protected function count");
        require(bodies.size() + imported <= result.m_functions.size(), "function/code count mismatch");
        std::map<uint32_t, std::unique_ptr<ProtectedFunction>> functions;
        for (size_t i = 0; i < count; i++) {
            const uint32_t index = reader.number(4);
            const uint64_t frameSize = reader.number(4);
            const uint64_t paramCount = reader.number(4);
            const uint64_t resultCount = reader.number(4);
            const uint64_t instructionCount = reader.number(4);
            const uint64_t mapCount = reader.number(4);
            require(index >= imported && index < imported + bodies.size(), "invalid protected function index");
            require(!functions.count(index), "duplicate protected function index");
            const auto& body = bodies[index - imported];
            require(body.size == sizeof(stubBody) && !memcmp(body.data, stubBody, sizeof(stubBody)), "protected function must have the canonical stub body");
            auto* moduleFunction = result.m_functions[index];
            checkFunctionType(moduleFunction);
            auto type = moduleFunction->functionType();
            require(frameSize >= 8 && frameSize <= UINT16_MAX && !(frameSize % 8)
                        && frameSize >= type->paramStackSize() && frameSize >= type->resultStackSize(), "invalid protected frame size");
            require(paramCount == type->param().size() && resultCount == type->result().size(), "protected signature count mismatch");
            require(mapCount == protectedOpcodeCount, "invalid opcode mapping size");
            for (auto value : type->param().types()) {
                require(reader.number(1) == typeCode(value), "protected parameter type mismatch");
            }
            for (auto value : type->result().types()) {
                require(reader.number(1) == typeCode(value), "protected return type mismatch");
            }
            std::unique_ptr<ProtectedFunction> function(new ProtectedFunction());
            function->frameSize = frameSize;
            function->resultCount = resultCount;
            function->resultWidth = resultCount ? (typeCode(type->result().types()[0]) == 0x7f ? 4 : 8) : 0;
            for (size_t j = 0; j < protectedOpcodeCount; j++) {
                const auto opcode = reader.number(2);
                require(opcode == j, "G1 requires an identity opcode mapping");
                function->opcodeMap[j] = opcode;
            }
            require(instructionCount && instructionCount <= reader.remaining() / protectedInstructionSize, "invalid protected instruction count");
            const size_t bytes = instructionCount * protectedInstructionSize;
            function->instructions.assign(reader.current, reader.current + bytes);
            reader.skip(bytes);
            validateInstructions(*function, type);
            functions.emplace(index, std::move(function));
        }
        require(!reader.remaining(), "trailing protected payload data");
        // Attach only after every record has passed validation.
        for (auto& entry : functions) {
            result.m_functions[entry.first]->setProtectedFunction(std::move(entry.second));
        }
        return std::string();
    } catch (const std::runtime_error& error) {
        return std::string("G1: ") + error.what();
    }
}
} // namespace Walrus
