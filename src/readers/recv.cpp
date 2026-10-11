#include "readers/recv.h"

#include "common/memory.h"

#include <Windows.h>

#include <array>
#include <optional>
#include <ranges>

namespace zonetrace::recv
{
namespace
{

constexpr std::string_view kSource = "recv";

// in the receive loop, the source address check against the zone object:
//   mov edx,[pGlobalNowZone]; mov ecx,[edi+558h]; add esp,4; cmp ecx,[edx+416Ch]
constexpr auto             kPattern = std::to_array<uint8_t>({ 0x8B, 0x15, 0, 0, 0, 0, 0x8B, 0x8F, 0x58, 0x05, 0x00, 0x00, 0x83, 0xC4, 0x04, 0x3B, 0x8A, 0x6C, 0x41, 0x00, 0x00 });
constexpr std::string_view kMask    = "xx????xxxxxxxxxxxxxxx";

// the function that counts a drop, its offset into the zone object differs between client builds:
//   mov eax,[esp+8]; cmp eax,0Ah; jb +5; mov eax,9; mov ecx,[esp+4]; mov edx,[ecx+eax*4+<drops>]; inc edx; mov [ecx+eax*4+<drops>],edx
constexpr auto             kDropsPattern = std::to_array<uint8_t>({ 0x83, 0xF8, 0x0A, 0x72, 0x05, 0xB8, 0x09, 0x00, 0x00, 0x00, 0x8B, 0x4C, 0x24, 0x04, 0x8B, 0x94, 0x81, 0, 0, 0, 0, 0x42, 0x89, 0x94, 0x81 });
constexpr std::string_view kDropsMask    = "xxxxxxxxxxxxxxxxx????xxxx";

// zone object fields; the object is zeroed and reused in place on every zone connect
constexpr uintptr_t kSocket         = 0x00; // the game's socket handle, new on every zone connect
constexpr uintptr_t kGameSequence   = 0x06; // uint16, the game's own datagram sequence
constexpr uintptr_t kServerSequence = 0x08; // uint16, the last server datagram sequence the game accepted
constexpr uintptr_t kServerAck      = 0x0A; // uint16, the server's ack of the game's sequence
constexpr uintptr_t kState          = 0x0C; // uint8, old datagrams are only dropped in state 3

// drop reasons the receive loop counts; the rest of the array is unused
constexpr size_t                                 kReasons     = 6;
constexpr std::array<std::string_view, kReasons> kReasonNames = {
    "wrong key",      // the payload's MD5 does not match after decrypting
    "malformed",      // bad size or the payload does not decompress
    "old datagram",   // sequence not newer than the last accepted one
    "empty packet",   // a sub-packet of size 0, the rest of the datagram is skipped
    "old sub-packet", // sub-packet sync not newer than the last accepted datagram
    "no handler",     // sub-packet id the game has no handler for
};

using Drops = std::array<uint32_t, kReasons>;

struct Snapshot
{
    uintptr_t socket;
    Drops     drops;
    uint16_t  gameSequence;
    uint16_t  serverSequence;
    uint16_t  serverAck;
    uint8_t   state;
};

LineSink  sink_{};
uintptr_t zone_{};
uintptr_t drops_{};
uintptr_t lastSocket_{};
Drops     last_{};

// guarded: the zone object can be torn down while zoning
auto capture() -> std::optional<Snapshot>
{
    if (zone_ == 0)
    {
        return std::nullopt;
    }

    __try
    {
        const auto zone = memory::read<uintptr_t>(zone_);
        if (zone == 0)
        {
            return std::nullopt;
        }

        return Snapshot{
            .socket         = memory::read<uintptr_t>(zone + kSocket),
            .drops          = memory::read<Drops>(zone + drops_),
            .gameSequence   = memory::read<uint16_t>(zone + kGameSequence),
            .serverSequence = memory::read<uint16_t>(zone + kServerSequence),
            .serverAck      = memory::read<uint16_t>(zone + kServerAck),
            .state          = memory::read<uint8_t>(zone + kState),
        };
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return std::nullopt;
    }
}

auto describe(const Snapshot& snapshot, const Drops* since) -> std::string
{
    std::string heading = "drops so far:";
    if (since != nullptr)
    {
        heading = "dropped";
    }

    std::string counts;
    for (size_t i = 0; i < kReasons; ++i)
    {
        auto count = snapshot.drops[i];
        if (since != nullptr)
        {
            count -= (*since)[i];
        }

        if (count == 0)
        {
            continue;
        }

        if (!counts.empty())
        {
            counts += ",";
        }

        counts += std::format(" {} {}", count, kReasonNames[i]);
    }

    if (counts.empty())
    {
        counts = " none";
    }

    return std::format("{}{} (server sequence {:04X} accepted, server acked {:04X}, game at {:04X}, state {})", heading, counts, snapshot.serverSequence, snapshot.serverAck, snapshot.gameSequence, static_cast<unsigned>(snapshot.state));
}

} // namespace

auto install(LineSink sink) -> Attempt
{
    const auto base = memory::moduleBase("FFXiMain.dll");
    if (base == 0)
    {
        return Attempt::NoModule;
    }

    const auto address = memory::findPattern(base, kPattern, kMask);
    const auto counter = memory::findPattern(base, kDropsPattern, kDropsMask);
    if (address == 0 || counter == 0)
    {
        return Attempt::NotFound;
    }

    sink_  = sink;
    zone_  = memory::read<uint32_t>(address + 2);
    drops_ = memory::read<uint32_t>(counter + 17);

    emit(sink_, kSource, "found the zone drop counters at +0x{:X}", drops_);
    return Attempt::Hooked;
}

void poll()
{
    const auto snapshot = capture();
    if (!snapshot)
    {
        return;
    }

    // every zone connect starts the counts over from zero
    bool restarted = snapshot->socket != lastSocket_;
    for (const auto [count, previous] : std::views::zip(snapshot->drops, last_))
    {
        restarted = restarted || count < previous;
    }

    if (restarted)
    {
        lastSocket_ = snapshot->socket;
        last_       = snapshot->drops;
        if (snapshot->drops != Drops{})
        {
            emit(sink_, kSource, "{}", describe(*snapshot, nullptr));
        }

        return;
    }

    if (snapshot->drops == last_)
    {
        return;
    }

    emit(sink_, kSource, "{}", describe(*snapshot, &last_));
    last_ = snapshot->drops;
}

void report()
{
    if (const auto snapshot = capture())
    {
        emit(sink_, kSource, "{}", describe(*snapshot, nullptr));
    }
}

} // namespace zonetrace::recv
