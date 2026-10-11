#include "recv.hpp"

#include "log.hpp"
#include "memory.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <format>

namespace zonetrace::recv
{
namespace
{

// drop reasons the receive loop counts; the rest of the array is unused
constexpr size_t      kReasons        = 6;
constexpr const char* names[kReasons] = {
    "wrong key",      // the payload's MD5 does not match after decrypting
    "malformed",      // bad size or the payload does not decompress
    "old datagram",   // sequence not newer than the last accepted one
    "empty packet",   // a sub-packet of size 0, the rest of the datagram is skipped
    "old sub-packet", // sub-packet sync not newer than the last accepted datagram
    "no handler",     // sub-packet id the game has no handler for
};

struct Snapshot
{
    uint32_t drops[kReasons];
    uint16_t gameSequence;
    uint16_t serverSequence;
    uint16_t serverAck;
    uint8_t  state;
};

LineSink         sink_{};
const uintptr_t* zone_{};
uintptr_t        drops_{};
uintptr_t        lastSocket_{};
uint32_t         last_[kReasons]{};

// guarded: the zone object can be torn down while zoning
auto read(uintptr_t* socket, Snapshot* snapshot) -> bool
{
    __try
    {
        const auto zone = *zone_;
        if (zone == 0)
        {
            return false;
        }

        *socket = *reinterpret_cast<const uintptr_t*>(zone + kSocket);
        std::memcpy(snapshot->drops, reinterpret_cast<const void*>(zone + drops_), sizeof(snapshot->drops));
        snapshot->gameSequence   = *reinterpret_cast<const uint16_t*>(zone + kGameSequence);
        snapshot->serverSequence = *reinterpret_cast<const uint16_t*>(zone + kServerSequence);
        snapshot->serverAck      = *reinterpret_cast<const uint16_t*>(zone + kServerAck);
        snapshot->state          = *reinterpret_cast<const uint8_t*>(zone + kState);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

void emit(const Snapshot& snapshot, const uint32_t* since)
{
    if (sink_ == nullptr)
    {
        return;
    }

    std::string line = timestamp() + " recv   ";
    if (since != nullptr)
    {
        line += "dropped";
    }
    else
    {
        line += "drops so far:";
    }

    bool any = false;
    for (size_t i = 0; i < kReasons; ++i)
    {
        auto count = snapshot.drops[i];
        if (since != nullptr)
        {
            count -= since[i];
        }

        if (count == 0)
        {
            continue;
        }

        if (any)
        {
            line += ",";
        }

        line += std::format(" {} {}", count, names[i]);
        any = true;
    }

    if (!any)
    {
        line += " none";
    }

    sink_(line + std::format(" (server sequence {:04X} accepted, server acked {:04X}, game at {:04X}, state {})", snapshot.serverSequence, snapshot.serverAck, snapshot.gameSequence, static_cast<unsigned>(snapshot.state)));
}

} // namespace

auto install(LineSink sink) -> Attempt
{
    const auto base = reinterpret_cast<uintptr_t>(::GetModuleHandleA("FFXiMain.dll"));
    if (base == 0)
    {
        return Attempt::NoModule;
    }

    const auto size    = memory::imageSize(base);
    const auto address = memory::findPattern(base, size, pattern, mask);
    const auto counter = memory::findPattern(base, size, dropsPattern, dropsMask);
    if (address == 0 || counter == 0)
    {
        return Attempt::NotFound;
    }

    uintptr_t global{};
    std::memcpy(&global, reinterpret_cast<const uint8_t*>(address) + 2, sizeof(uint32_t));

    uint32_t drops{};
    std::memcpy(&drops, reinterpret_cast<const uint8_t*>(counter) + 17, sizeof(drops));

    sink_  = sink;
    zone_  = reinterpret_cast<const uintptr_t*>(global);
    drops_ = drops;

    sink_(std::format("{} recv   found the zone drop counters at +0x{:X}", timestamp(), drops));
    return Attempt::Hooked;
}

void poll()
{
    if (zone_ == nullptr)
    {
        return;
    }

    uintptr_t socket{};
    Snapshot  snapshot{};
    if (!read(&socket, &snapshot))
    {
        return;
    }

    // every zone connect starts the counts over from zero
    bool restarted = socket != lastSocket_;
    for (size_t i = 0; i < kReasons; ++i)
    {
        restarted = restarted || snapshot.drops[i] < last_[i];
    }

    if (restarted)
    {
        lastSocket_ = socket;
        std::memcpy(last_, snapshot.drops, sizeof(last_));
        const auto dropped = std::any_of(
            snapshot.drops,
            snapshot.drops + kReasons - 1,
            [](uint32_t count)
            {
                return count != 0;
            });
        if (dropped)
        {
            emit(snapshot, nullptr);
        }

        return;
    }

    // packets without a handler come and go in normal play, they only show alongside the others
    if (std::memcmp(last_, snapshot.drops, sizeof(uint32_t) * (kReasons - 1)) == 0)
    {
        return;
    }

    emit(snapshot, last_);
    std::memcpy(last_, snapshot.drops, sizeof(last_));
}

void report()
{
    if (zone_ == nullptr)
    {
        return;
    }

    uintptr_t socket{};
    Snapshot  snapshot{};
    if (read(&socket, &snapshot))
    {
        emit(snapshot, nullptr);
    }
}

} // namespace zonetrace::recv
