#include "common/memory.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <vector>

namespace zonetrace::memory
{
namespace
{

struct Slot
{
    uintptr_t address;
    uintptr_t original;
};

struct Region
{
    uintptr_t begin;
    uintptr_t end;
};

std::vector<Slot> slots_;

auto imageSize(uintptr_t base) -> size_t
{
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto nt  = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    return nt->OptionalHeader.SizeOfImage;
}

auto regions(uintptr_t base, DWORD protections) -> std::vector<Region>
{
    std::vector<Region> found;
    uintptr_t           address = base;
    const uintptr_t     end     = base + imageSize(base);
    while (address < end)
    {
        MEMORY_BASIC_INFORMATION info{};
        if (::VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info)) == 0)
        {
            break;
        }

        const uintptr_t regionEnd = (std::min)(static_cast<uintptr_t>(reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize), end);
        if (info.State == MEM_COMMIT && (info.Protect & protections) != 0)
        {
            found.push_back({ .begin = address, .end = regionEnd });
        }

        address = regionEnd;
    }

    return found;
}

auto matches(const uint8_t* bytes, std::span<const uint8_t> pattern, std::string_view mask) -> bool
{
    for (size_t i = 0; i < mask.size(); ++i)
    {
        if (mask[i] != '?' && bytes[i] != pattern[i])
        {
            return false;
        }
    }

    return true;
}

auto write(uintptr_t address, std::span<const std::byte> bytes, DWORD protection) -> bool
{
    DWORD previous = 0;
    if (!::VirtualProtect(reinterpret_cast<void*>(address), bytes.size(), protection, &previous))
    {
        return false;
    }

    std::ranges::copy(bytes, reinterpret_cast<std::byte*>(address));
    ::VirtualProtect(reinterpret_cast<void*>(address), bytes.size(), previous, &previous);
    return true;
}

auto writeCode(uintptr_t address, std::span<const uint8_t> bytes) -> bool
{
    const auto written = write(address, std::as_bytes(bytes), PAGE_EXECUTE_READWRITE);
    ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(address), bytes.size());
    return written;
}

} // namespace

auto moduleBase(const char* name) -> uintptr_t
{
    return reinterpret_cast<uintptr_t>(::GetModuleHandleA(name));
}

auto polcore() -> Module
{
    for (const auto name : { "polcore.dll", "polcoreeu.dll" })
    {
        if (const auto base = moduleBase(name); base != 0)
        {
            return { .name = name, .base = base };
        }
    }

    return {};
}

// scans committed, readable pages only: a module's unpacked code may still be mid-write while it loads
auto findPattern(uintptr_t base, std::span<const uint8_t> pattern, std::string_view mask) -> uintptr_t
{
    for (const auto [begin, end] : regions(base, PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE))
    {
        for (auto address = begin; address + mask.size() <= end; ++address)
        {
            if (matches(reinterpret_cast<const uint8_t*>(address), pattern, mask))
            {
                return address;
            }
        }
    }

    return 0;
}

auto patchJump(uintptr_t address, uintptr_t target, std::span<uint8_t, 5> original) -> bool
{
    std::ranges::copy_n(reinterpret_cast<const uint8_t*>(address), original.size(), original.begin());

    std::array<uint8_t, 5> jump{ 0xE9 };
    const auto             relative = static_cast<int32_t>(target - (address + jump.size()));
    std::memcpy(jump.data() + 1, &relative, sizeof(relative));

    return writeCode(address, jump);
}

auto restoreBytes(uintptr_t address, std::span<const uint8_t> original) -> bool
{
    return writeCode(address, original);
}

auto patchSlots(uintptr_t base, uintptr_t function, uintptr_t hook) -> int
{
    if (function == 0)
    {
        return 0;
    }

    int patched = 0;
    for (const auto [begin, end] : regions(base, PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY))
    {
        for (auto address = begin; address + sizeof(uintptr_t) <= end; address += sizeof(uintptr_t))
        {
            if (read<uintptr_t>(address) == function && write(address, std::as_bytes(std::span(&hook, 1)), PAGE_READWRITE))
            {
                slots_.push_back({ .address = address, .original = function });
                ++patched;
            }
        }
    }

    return patched;
}

void restoreSlots()
{
    for (const auto& slot : slots_)
    {
        write(slot.address, std::as_bytes(std::span(&slot.original, 1)), PAGE_READWRITE);
    }

    slots_.clear();
}

} // namespace zonetrace::memory
