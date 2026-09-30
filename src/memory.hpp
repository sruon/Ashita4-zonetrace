#pragma once

#include <cstddef>
#include <cstdint>

namespace zonetrace::memory
{
    auto imageSize(uintptr_t base) -> size_t;

    // first match of `pattern` in the module's committed, readable pages; mask 'x' compares the byte, '?' skips it
    auto findPattern(uintptr_t base, size_t size, const uint8_t* pattern, const char* mask) -> uintptr_t;

    // overwrites the 5 bytes at `address` with a jump to `target`; `original` receives the bytes replaced
    bool patchJump(uintptr_t address, uintptr_t target, uint8_t* original);
    bool restoreBytes(uintptr_t address, const uint8_t* original, size_t size);

    // points every pointer-sized data slot in the module that holds `function` at `hook`; returns the number patched
    auto patchSlots(uintptr_t moduleBase, uintptr_t function, uintptr_t hook) -> int;
    void restoreSlots();
} // namespace zonetrace::memory
