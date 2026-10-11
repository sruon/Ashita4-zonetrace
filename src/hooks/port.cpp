#include "hooks/port.h"

#include "common/memory.h"

#include <array>

namespace zonetrace::port
{
namespace
{

using GetPortFunction = uint32_t(__cdecl*)();

constexpr std::string_view kSource   = "port";
constexpr int              kBasePort = 54090;

// the setter, the getter right after it and the two globals they touch
//   8B 44 24 04  05 4A D3 00 00  A3 <serverPort>  C3 90
//   A1 <gameIndex>  85 C0  7D 07  66 A1 <serverPort>  C3 ...
constexpr auto             kPattern = std::to_array<uint8_t>({ 0x8B, 0x44, 0x24, 0x04, 0x05, 0x4A, 0xD3, 0x00, 0x00, 0xA3, 0, 0, 0, 0, 0xC3, 0x90, 0xA1, 0, 0, 0, 0, 0x85, 0xC0, 0x7D, 0x07, 0x66, 0xA1 });
constexpr std::string_view kMask    = "xxxxxxxxxx????xxx????xxxxxx";

struct Layout
{
    uintptr_t setter{};     // sqInetSetSafeUdpPortOffset(n): serverPort = 54090 + n
    uintptr_t getter{};     // sqInetGetSafeUdpPort(): the value FFXiMain binds
    uintptr_t gameIndex{};  // int, -1 when the viewer did not set one
    uintptr_t serverPort{}; // uint32
};

Layout                 layout_;
LineSink               sink_{};
std::array<uint8_t, 5> setterOriginal_{};
GetPortFunction        realGetPort_{};
int32_t                lastGameIndex_{};

auto gameIndex() -> int32_t
{
    return *reinterpret_cast<const int32_t*>(layout_.gameIndex);
}

auto serverPort() -> uint32_t
{
    return *reinterpret_cast<const uint32_t*>(layout_.serverPort);
}

auto outcome(bool succeeded) -> const char*
{
    if (succeeded)
    {
        return "ok";
    }

    return "failed";
}

auto __cdecl hookedGetPort() -> uint32_t
{
    const auto port = realGetPort_();
    emit(sink_, kSource, "game asks for its port: {} (game index {}, server asked for {})", port & 0xFFFF, gameIndex(), serverPort());
    return port;
}

// replaces the whole setter (mov eax,[esp+4]; add eax,54090; mov [serverPort],eax; ret), so no trampoline is needed
void __cdecl hookedSetOffset(int offset)
{
    const auto port = static_cast<uint32_t>(offset + kBasePort);

    *reinterpret_cast<uint32_t*>(layout_.serverPort) = port;
    emit(sink_, kSource, "server assigned slot {}, the game will bind {} from its next socket on", offset + 1, port);
}

} // namespace

auto install(LineSink sink) -> Attempt
{
    const auto [name, base] = memory::polcore();
    if (base == 0)
    {
        return Attempt::NoModule;
    }

    const auto address = memory::findPattern(base, kPattern, kMask);
    if (address == 0)
    {
        return Attempt::NotFound;
    }

    sink_   = sink;
    layout_ = {
        .setter     = address,
        .getter     = address + 16,
        .gameIndex  = memory::read<uint32_t>(address + 17),
        .serverPort = memory::read<uint32_t>(address + 10),
    };

    realGetPort_   = reinterpret_cast<GetPortFunction>(layout_.getter);
    lastGameIndex_ = gameIndex();

    const auto slots  = memory::patchSlots(base, layout_.getter, reinterpret_cast<uintptr_t>(&hookedGetPort));
    const auto setter = memory::patchJump(layout_.setter, reinterpret_cast<uintptr_t>(&hookedSetOffset), setterOriginal_);
    emit(sink_, kSource, "hooked {}: game index {}, port {} ({} getter slots, setter {})", name, lastGameIndex_, realGetPort_() & 0xFFFF, slots, outcome(setter));
    return Attempt::Hooked;
}

void poll()
{
    if (layout_.getter == 0)
    {
        return;
    }

    if (const auto index = gameIndex(); index != lastGameIndex_)
    {
        emit(sink_, kSource, "game index changed {} -> {}", lastGameIndex_, index);
        lastGameIndex_ = index;
    }
}

void remove()
{
    if (layout_.setter != 0)
    {
        memory::restoreBytes(layout_.setter, setterOriginal_);
    }

    layout_ = {};
    sink_   = nullptr;
}

} // namespace zonetrace::port
