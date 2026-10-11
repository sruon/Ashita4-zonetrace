#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace zonetrace::memory
{

struct Module
{
    std::string_view name;
    uintptr_t        base{};
};

auto moduleBase(const char* name) -> uintptr_t;
auto polcore() -> Module; // polcore.dll or polcoreeu.dll, whichever is loaded

auto findPattern(uintptr_t base, std::span<const uint8_t> pattern, std::string_view mask) -> uintptr_t; // first match of `pattern` in the module's committed, readable pages; mask 'x' compares the byte, '?' skips it

template <typename T>
auto read(uintptr_t address) -> T
{
    T value{};
    std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(T));
    return value;
}

auto patchJump(uintptr_t address, uintptr_t target, std::span<uint8_t, 5> original) -> bool; // overwrites the 5 bytes at `address` with a jump to `target`; `original` receives the bytes replaced
auto restoreBytes(uintptr_t address, std::span<const uint8_t> original) -> bool;

auto patchSlots(uintptr_t base, uintptr_t function, uintptr_t hook) -> int; // points every pointer-sized data slot in the module that holds `function` at `hook`; returns the number patched
void restoreSlots();

} // namespace zonetrace::memory
