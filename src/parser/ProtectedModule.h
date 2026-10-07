/* Copyright (c) 2026 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0. */
#ifndef __WalrusProtectedModule__
#define __WalrusProtectedModule__
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
namespace Walrus {
class Module;
struct WASMParsingResult;
enum class ProtectionMode : uint32_t { Identity = 0, Permuted = 1 };
struct ProtectionOptions {
    ProtectionMode mode = ProtectionMode::Identity;
    // Keep the original CLI's byte-for-byte v1 output; explicit modes default to v2.
    bool version2 = false;
    bool version3 = false;
    bool extended = false;
    bool floatingPoint = false;
    bool fusion = false;
    uint64_t seed = 0;
};
// Input must first pass the ordinary Wasm parser. Function indices include imports.
std::string packProtectedModule(Module* module, const uint8_t* data, size_t size,
                                const std::vector<uint32_t>& functions, const ProtectionOptions& options,
                                std::vector<uint8_t>& output);
std::string loadProtectedFunctions(WASMParsingResult& result, const uint8_t* data, size_t size, bool useJIT);
} // namespace Walrus
#endif
