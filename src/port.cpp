#include "port.hpp"

#include "log.hpp"
#include "memory.hpp"

#include <Windows.h>

#include <cstdio>

namespace zonetrace::port
{
    namespace
    {
        using GetPortFunction = uint32_t(__cdecl*)();

        Layout layout_;
        LineSink sink_{};
        uint8_t setterOriginal_[5]{};
        GetPortFunction realGetPort{};
        int32_t lastGameIndex_{};

        template <typename... Args>
        void emit(const char* pattern, Args... args)
        {
            char buffer[256];
            snprintf(buffer, sizeof(buffer), pattern, args...);
            if (sink_ != nullptr)
                sink_(timestamp() + " port   " + buffer);
        }

        auto gameIndex() -> int32_t
        {
            return *reinterpret_cast<const int32_t*>(layout_.gameIndex);
        }

        auto serverPort() -> uint32_t
        {
            return *reinterpret_cast<const uint32_t*>(layout_.serverPort);
        }

        uint32_t __cdecl hookedGetPort()
        {
            const auto port = realGetPort();
            emit("game asks for its port: %u (game index %d, server asked for %u)", port & 0xFFFF, gameIndex(), serverPort());
            return port;
        }

        // replaces the whole setter (mov eax,[esp+4]; add eax,54090; mov [serverPort],eax; ret), so no trampoline is needed
        void __cdecl hookedSetOffset(int offset)
        {
            *reinterpret_cast<uint32_t*>(layout_.serverPort) = static_cast<uint32_t>(offset + 54090);
            emit("server assigned slot %d, the game will bind %u from its next socket on", offset + 1, offset + 54090);
        }
    } // namespace

    auto install(LineSink sink) -> Attempt
    {

        for (const auto name : { "polcore.dll", "polcoreeu.dll" })
        {
            const auto base = reinterpret_cast<uintptr_t>(::GetModuleHandleA(name));
            if (base == 0)
                continue;

            const auto address = memory::findPattern(base, memory::imageSize(base), pattern, mask);
            if (address == 0)
                return Attempt::NotFound;

            sink_   = sink;
            layout_ = parse(reinterpret_cast<const uint8_t*>(address), sizeof(pattern), address);

            realGetPort     = reinterpret_cast<GetPortFunction>(layout_.getter);
            lastGameIndex_ = gameIndex();

            const auto slots  = memory::patchSlots(base, layout_.getter, reinterpret_cast<uintptr_t>(&hookedGetPort));
            const auto setter = memory::patchJump(layout_.setter, reinterpret_cast<uintptr_t>(&hookedSetOffset), setterOriginal_);
            emit("hooked %s: game index %d, port %u (%d getter slots, setter %s)", name, lastGameIndex_, realGetPort() & 0xFFFF, slots, setter ? "ok" : "failed");
            return Attempt::Hooked;
        }

        return Attempt::NoModule;
    }

    void poll()
    {
        if (layout_.getter == 0)
            return;

        const auto index = gameIndex();
        if (index != lastGameIndex_)
        {
            emit("game index changed %d -> %d", lastGameIndex_, index);
            lastGameIndex_ = index;
        }
    }

    void remove()
    {
        if (layout_.setter != 0)
            memory::restoreBytes(layout_.setter, setterOriginal_, sizeof(setterOriginal_));

        layout_ = {};
        sink_   = nullptr;
    }
} // namespace zonetrace::port
