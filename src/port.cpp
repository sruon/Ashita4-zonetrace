#include "port.hpp"

#include "log.hpp"
#include "memory.hpp"

#include <Windows.h>

#include <format>

namespace zonetrace::port
{
namespace
{

using GetPortFunction = uint32_t(__cdecl*)();

Layout          layout_;
LineSink        sink_{};
uint8_t         setterOriginal_[5]{};
GetPortFunction realGetPort_{};
int32_t         lastGameIndex_{};

template <typename... Args>
void emit(std::format_string<Args...> format, Args&&... args)
{
    if (sink_ != nullptr)
    {
        sink_(timestamp() + " port   " + std::format(format, std::forward<Args>(args)...));
    }
}

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
    emit("game asks for its port: {} (game index {}, server asked for {})", port & 0xFFFF, gameIndex(), serverPort());
    return port;
}

// replaces the whole setter (mov eax,[esp+4]; add eax,54090; mov [serverPort],eax; ret), so no trampoline is needed
void __cdecl hookedSetOffset(int offset)
{
    *reinterpret_cast<uint32_t*>(layout_.serverPort) = static_cast<uint32_t>(offset + 54090);
    emit("server assigned slot {}, the game will bind {} from its next socket on", offset + 1, static_cast<unsigned>(offset + 54090));
}

} // namespace

auto install(LineSink sink) -> Attempt
{
    for (const auto name : { "polcore.dll", "polcoreeu.dll" })
    {
        const auto base = reinterpret_cast<uintptr_t>(::GetModuleHandleA(name));
        if (base == 0)
        {
            continue;
        }

        const auto address = memory::findPattern(base, memory::imageSize(base), pattern, mask);
        if (address == 0)
        {
            return Attempt::NotFound;
        }

        sink_   = sink;
        layout_ = parse(reinterpret_cast<const uint8_t*>(address), sizeof(pattern), address);

        realGetPort_   = reinterpret_cast<GetPortFunction>(layout_.getter);
        lastGameIndex_ = gameIndex();

        const auto slots  = memory::patchSlots(base, layout_.getter, reinterpret_cast<uintptr_t>(&hookedGetPort));
        const auto setter = memory::patchJump(layout_.setter, reinterpret_cast<uintptr_t>(&hookedSetOffset), setterOriginal_);
        emit("hooked {}: game index {}, port {} ({} getter slots, setter {})", name, lastGameIndex_, realGetPort_() & 0xFFFF, slots, outcome(setter));
        return Attempt::Hooked;
    }

    return Attempt::NoModule;
}

void poll()
{
    if (layout_.getter == 0)
    {
        return;
    }

    const auto index = gameIndex();
    if (index != lastGameIndex_)
    {
        emit("game index changed {} -> {}", lastGameIndex_, index);
        lastGameIndex_ = index;
    }
}

void remove()
{
    if (layout_.setter != 0)
    {
        memory::restoreBytes(layout_.setter, setterOriginal_, sizeof(setterOriginal_));
    }

    layout_ = {};
    sink_   = nullptr;
}

} // namespace zonetrace::port
