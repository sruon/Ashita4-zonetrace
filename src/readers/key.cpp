#include "readers/key.h"

#include "common/memory.h"

#include <Windows.h>

#include <array>
#include <optional>

namespace zonetrace::key
{
namespace
{

using Value = std::array<uint8_t, 16>;

constexpr std::string_view kSource = "key";

// the getter FFXiMain calls: mov eax,[esp+4]; push 16; push <value>; push eax; call memcpy; add esp,12; ret
constexpr auto             kPattern = std::to_array<uint8_t>({ 0x8B, 0x44, 0x24, 0x04, 0x6A, 0x10, 0x68, 0, 0, 0, 0, 0x50, 0xE8, 0, 0, 0, 0, 0x83, 0xC4, 0x0C, 0xC3 });
constexpr std::string_view kMask    = "xxxxxxx????xx????xxxx";

// the lobby counter, +2 per zone connect. found through the zone connect step that loads the main system struct:
//   mov eax,[pGcMainSys]; mov dword [eax+136ACh],0; mov eax,[dllsw]; test eax,eax; jnz +35h; call
constexpr auto             kCounterPattern = std::to_array<uint8_t>({ 0xA1, 0, 0, 0, 0, 0xC7, 0x80, 0xAC, 0x36, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA1, 0, 0, 0, 0, 0x85, 0xC0, 0x75, 0x35, 0xE8 });
constexpr std::string_view kCounterMask    = "x????xxxxxxxxxxx????xxxxx";

constexpr uintptr_t kCounterOffset = 0x136DC + 0x138; // lobby work copy at +0x136DC, counter at +0x138 into it

LineSink             sink_{};
uintptr_t            value_{};
std::optional<Value> last_;

uintptr_t mainSystem_{};
uint32_t  lastCounter_{};

// FNV-1a over the 16 bytes; a server admin computes the same from the first 16 bytes of accounts_sessions.session_key
auto fingerprint(const Value& value) -> uint32_t
{
    uint32_t hash = 2166136261u;
    for (const auto byte : value)
    {
        hash = (hash ^ byte) * 16777619u;
    }

    return hash;
}

// guarded: the struct is allocated at login and freed on logout
auto counter() -> uint32_t
{
    __try
    {
        const auto system = memory::read<uintptr_t>(mainSystem_);
        if (system == 0)
        {
            return 0;
        }

        return memory::read<uint32_t>(system + kCounterOffset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
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

    const auto value = memory::read<uint32_t>(address + 7);

    sink_  = sink;
    value_ = value;

    emit(sink_, kSource, "found the session key value in {} at +0x{:X}", name, static_cast<unsigned>(value - base));
    poll();
    return Attempt::Hooked;
}

auto installCounter(LineSink sink) -> Attempt
{
    const auto base = memory::moduleBase("FFXiMain.dll");
    if (base == 0)
    {
        return Attempt::NoModule;
    }

    const auto address = memory::findPattern(base, kCounterPattern, kCounterMask);
    if (address == 0)
    {
        return Attempt::NotFound;
    }

    sink_       = sink;
    mainSystem_ = memory::read<uint32_t>(address + 1);
    return Attempt::Hooked;
}

void poll()
{
    // the counter alone is not secret
    if (mainSystem_ != 0)
    {
        if (const auto current = counter(); current != 0 && current != lastCounter_)
        {
            int delta = 0;
            if (lastCounter_ != 0)
            {
                delta = static_cast<int>(current - lastCounter_);
            }

            emit(sink_, kSource, "zone key counter {:08X} ({:+})", current, delta);
            lastCounter_ = current;
        }
    }

    if (value_ == 0)
    {
        return;
    }

    const auto current = memory::read<Value>(value_);
    if (current == last_)
    {
        return;
    }

    last_ = current;

    if (current == Value{})
    {
        emit(sink_, kSource, "session key value is all zeros (server did not send one yet)");
    }
    else
    {
        emit(sink_, kSource, "session key value fingerprint {:08X}", fingerprint(current));
    }
}

} // namespace zonetrace::key
