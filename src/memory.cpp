#include "memory.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstring>
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

        std::vector<Slot> slots_;

        bool write(uintptr_t address, const void* bytes, size_t size, DWORD protection)
        {
            DWORD previous = 0;
            if (!::VirtualProtect(reinterpret_cast<void*>(address), size, protection, &previous))
                return false;

            std::memcpy(reinterpret_cast<void*>(address), bytes, size);
            ::VirtualProtect(reinterpret_cast<void*>(address), size, previous, &previous);
            return true;
        }
    } // namespace

    auto imageSize(uintptr_t base) -> size_t
    {
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        const auto nt  = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        return nt->OptionalHeader.SizeOfImage;
    }

    // scans committed, readable pages only: a module's unpacked code may still be mid-write while it loads
    auto findPattern(uintptr_t base, size_t size, const uint8_t* pattern, const char* mask) -> uintptr_t
    {
        const auto length   = std::strlen(mask);
        uintptr_t address   = base;
        const uintptr_t end = base + size;
        while (address < end)
        {
            MEMORY_BASIC_INFORMATION info{};
            if (::VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info)) == 0)
                break;

            const uintptr_t regionEnd = (std::min)(static_cast<uintptr_t>(reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize), end);
            const bool readable       = info.State == MEM_COMMIT && (info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE)) != 0;
            if (readable && regionEnd - address >= length)
            {
                for (auto p = address; p + length <= regionEnd; ++p)
                {
                    const auto bytes = reinterpret_cast<const uint8_t*>(p);
                    size_t i         = 0;
                    while (i < length && (mask[i] == '?' || bytes[i] == pattern[i]))
                        ++i;
                    if (i == length)
                        return p;
                }
            }

            address = regionEnd;
        }

        return 0;
    }

    bool patchJump(uintptr_t address, uintptr_t target, uint8_t* original)
    {
        std::memcpy(original, reinterpret_cast<const void*>(address), 5);

        uint8_t jump[5]{ 0xE9 };
        const auto relative = static_cast<int32_t>(target - (address + 5));
        std::memcpy(jump + 1, &relative, sizeof(relative));

        const auto written = write(address, jump, sizeof(jump), PAGE_EXECUTE_READWRITE);
        ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(address), sizeof(jump));
        return written;
    }

    bool restoreBytes(uintptr_t address, const uint8_t* original, size_t size)
    {
        const auto written = write(address, original, size, PAGE_EXECUTE_READWRITE);
        ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(address), size);
        return written;
    }

    auto patchSlots(uintptr_t moduleBase, uintptr_t function, uintptr_t hook) -> int
    {
        if (function == 0)
            return 0;

        int patched         = 0;
        uintptr_t address   = moduleBase;
        const uintptr_t end = moduleBase + imageSize(moduleBase);
        while (address < end)
        {
            MEMORY_BASIC_INFORMATION info{};
            if (::VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info)) == 0)
                break;

            const uintptr_t regionEnd = (std::min)(static_cast<uintptr_t>(reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize), end);
            const bool data           = info.State == MEM_COMMIT && (info.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY)) != 0;
            if (data)
            {
                for (auto p = address; p + sizeof(uintptr_t) <= regionEnd; p += sizeof(uintptr_t))
                {
                    if (*reinterpret_cast<const uintptr_t*>(p) == function && write(p, &hook, sizeof(hook), PAGE_READWRITE))
                    {
                        slots_.push_back({ p, function });
                        ++patched;
                    }
                }
            }

            address = regionEnd;
        }

        return patched;
    }

    void restoreSlots()
    {
        for (const auto& slot : slots_)
            write(slot.address, &slot.original, sizeof(slot.original), PAGE_READWRITE);

        slots_.clear();
    }
} // namespace zonetrace::memory
