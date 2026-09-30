#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace zonetrace
{
    using LineSink = void (*)(const std::string& line);

    enum class Attempt
    {
        NoModule, // not loaded yet, keep waiting
        NotFound, // loaded, but nothing to hook: still unpacking, or already hooked by something else
        Hooked,
    };

    // how the game picks its local UDP port: FFXiMain asks polcore, polcore answers 54090 + game index when the viewer
    // set one, else the port the PlayOnline server requested in the login notice, else 54090
    namespace port
    {
        struct Layout
        {
            uintptr_t setter{};     // sqInetSetSafeUdpPortOffset(n): serverPort = 54090 + n
            uintptr_t getter{};     // sqInetGetSafeUdpPort(): the value FFXiMain binds
            uintptr_t gameIndex{};  // int, -1 when the viewer did not set one
            uintptr_t serverPort{}; // uint32
        };

        // the setter, the getter right after it and the two globals they touch
        //   8B 44 24 04  05 4A D3 00 00  A3 <serverPort>  C3 90
        //   A1 <gameIndex>  85 C0  7D 07  66 A1 <serverPort>  C3 ...
        constexpr uint8_t pattern[] = { 0x8B, 0x44, 0x24, 0x04, 0x05, 0x4A, 0xD3, 0x00, 0x00, 0xA3, 0, 0, 0, 0, 0xC3, 0x90, 0xA1, 0, 0, 0, 0, 0x85, 0xC0, 0x7D, 0x07, 0x66, 0xA1 };
        constexpr char mask[]       = "xxxxxxxxxx????xxx????xxxxxx";

        inline auto parse(const uint8_t* bytes, size_t size, uintptr_t address) -> Layout
        {
            if (size < sizeof(pattern))
                return {};

            for (size_t i = 0; i < sizeof(pattern); ++i)
            {
                if (mask[i] == 'x' && bytes[i] != pattern[i])
                    return {};
            }

            Layout layout;
            layout.setter = address;
            layout.getter = address + 16;
            std::memcpy(&layout.serverPort, bytes + 10, sizeof(uint32_t));
            std::memcpy(&layout.gameIndex, bytes + 17, sizeof(uint32_t));
            return layout;
        }

        auto install(LineSink sink) -> Attempt;
        void poll(); // logs when the viewer or the server changes the port choice
        void remove();
    } // namespace port
} // namespace zonetrace
