#include "plugin.h"

#include "common/log.h"
#include "common/memory.h"
#include "hooks/port.h"
#include "hooks/sockets.h"
#include "readers/key.h"
#include "readers/recv.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <format>
#include <optional>
#include <string_view>

namespace zonetrace
{
namespace
{

using namespace std::chrono_literals;

using Clock = std::chrono::steady_clock;

constexpr int  kAttempts           = 500; // give up on a module that still has nothing to hook after this many tries
constexpr auto kInstallInterval    = 20ms;
constexpr auto kPollInterval       = 500ms;
constexpr auto kNoCharacterWarning = 15s;
constexpr auto kZoneSettle         = 2s;

struct Identity
{
    uint32_t             id;
    uint16_t             zone;
    std::array<char, 24> name;
};

Log log_;

void write(const std::string& line)
{
    log_.line(line);
}

// the directory this dll lives in; the plugin id is its module base
auto moduleDirectory(uint32_t id) -> std::string
{
    std::array<char, MAX_PATH> path{};
    ::GetModuleFileNameA(reinterpret_cast<HMODULE>(static_cast<uintptr_t>(id)), path.data(), MAX_PATH);

    const std::string_view directory = path.data();
    return std::string(directory.substr(0, directory.find_last_of("\\/")));
}

// reads the player's own party slot. guarded: the game rewrites this memory while zoning
auto readIdentity(IAshitaCore* core) -> std::optional<Identity>
{
    __try
    {
        const auto memory = core->GetMemoryManager();
        if (memory == nullptr)
        {
            return std::nullopt;
        }

        const auto party = memory->GetParty();
        if (party == nullptr || party->GetMemberIsActive(0) == 0)
        {
            return std::nullopt;
        }

        const auto name = party->GetMemberName(0);
        if (name == nullptr)
        {
            return std::nullopt;
        }

        Identity identity{
            .id   = party->GetMemberServerId(0),
            .zone = party->GetMemberZone(0),
        };
        for (size_t i = 0; i + 1 < identity.name.size() && name[i] >= 0x20 && name[i] < 0x7F; ++i)
        {
            identity.name[i] = name[i];
        }

        if (identity.id == 0 || identity.name[0] == 0)
        {
            return std::nullopt;
        }

        return identity;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return std::nullopt;
    }
}

// server logs are usually in UTC, the lines here are local time
auto clock() -> std::string
{
    SYSTEMTIME local{};
    ::GetLocalTime(&local);

    TIME_ZONE_INFORMATION zone{};
    const auto            daylight = ::GetTimeZoneInformation(&zone) == TIME_ZONE_ID_DAYLIGHT;

    auto        bias     = zone.StandardBias;
    const auto* zoneName = zone.StandardName;
    if (daylight)
    {
        bias     = zone.DaylightBias;
        zoneName = zone.DaylightName;
    }

    const auto offset = -(zone.Bias + bias); // minutes east of UTC

    std::array<char, 64> name{};
    ::WideCharToMultiByte(CP_ACP, 0, zoneName, -1, name.data(), static_cast<int>(name.size()) - 1, nullptr, nullptr);

    char sign = '+';
    if (offset < 0)
    {
        sign = '-';
    }

    return std::format("{:04}-{:02}-{:02}, all times are local: UTC{}{:02}:{:02} ({})", local.wYear, local.wMonth, local.wDay, sign, std::abs(offset) / 60, std::abs(offset) % 60, name.data());
}

} // namespace

const char* ZoneTrace::GetName(void) const
{
    return "zonetrace";
}

const char* ZoneTrace::GetAuthor(void) const
{
    return "sruon";
}

const char* ZoneTrace::GetDescription(void) const
{
    return "Logs which UDP port the game uses for each zone and whether the server answers, to diagnose black screens and disconnects.";
}

const char* ZoneTrace::GetLink(void) const
{
    return "";
}

double ZoneTrace::GetVersion(void) const
{
    // 1.2.3 -> 1.0203, so every release compares higher than the last
    return ZONETRACE_VERSION_MAJOR + ZONETRACE_VERSION_MINOR / 100.0 + ZONETRACE_VERSION_PATCH / 10000.0;
}

uint32_t ZoneTrace::GetFlags(void) const
{
    return static_cast<uint32_t>(Ashita::PluginFlags::UseCommands);
}

bool ZoneTrace::Initialize(IAshitaCore* core, ILogManager* logger, uint32_t id)
{
    core_ = core;

    const auto directory = moduleDirectory(id) + "\\logs";
    if (!log_.open(directory))
    {
        if (logger != nullptr)
        {
            logger->Logf(static_cast<uint32_t>(Ashita::LogLevel::Error), "zonetrace", "cannot open a log in %s", directory.c_str());
        }

        return false;
    }

    emit(&write, "zonetrace", "{}, {}", ZONETRACE_VERSION, clock());

    // POL plugins load before polcore and the game; both unpack themselves, so keep trying until the hooks take
    stop_    = false;
    watcher_ = std::thread(
        [this]
        {
            struct Hook
            {
                auto (*install)(LineSink sink) -> Attempt;
                std::string_view source;
                std::string_view failure;
                int              misses{};
                bool             hooked{};
            };

            std::array hooks{
                Hook{ .install = &port::install, .source = "port", .failure = "cannot find polcore's port chooser: client updated, or another plugin already hooked it" },
                Hook{ .install = &sockets::install, .source = "socket", .failure = "cannot hook the game's sockets: another plugin already hooked them" },
                Hook{ .install = &key::install, .source = "key", .failure = "cannot find polcore's session key value: client updated" },
                Hook{ .install = &key::installCounter, .source = "key", .failure = "cannot find FFXiMain's zone key counter: client updated" },
                Hook{ .install = &recv::install, .source = "recv", .failure = "cannot find FFXiMain's zone object: client updated" },
            };

            const auto pending = [](const Hook& hook) -> bool
            {
                return !hook.hooked && hook.misses < kAttempts;
            };

            while (!stop_)
            {
                for (auto& hook : hooks)
                {
                    if (!pending(hook))
                    {
                        continue;
                    }

                    const auto attempt = hook.install(&write);
                    hook.hooked        = attempt == Attempt::Hooked;
                    if (attempt == Attempt::NotFound && ++hook.misses == kAttempts)
                    {
                        emit(&write, hook.source, "{}", hook.failure);
                    }
                }

                port::poll();
                key::poll();
                recv::poll();
                sockets::poll();
                identify();

                auto delay = kPollInterval;
                if (std::ranges::any_of(hooks, pending))
                {
                    delay = kInstallInterval;
                }

                std::this_thread::sleep_for(delay);
            }
        });

    return true;
}

void ZoneTrace::Release(void)
{
    stop_ = true;
    if (watcher_.joinable())
    {
        watcher_.join();
    }

    port::remove();
    memory::restoreSlots();
    emit(&write, "zonetrace", "unloaded");
    log_.close();
}

bool ZoneTrace::HandleCommand(int32_t mode, const char* command, bool injected)
{
    UNREFERENCED_PARAMETER(mode);
    UNREFERENCED_PARAMETER(injected);

    std::string_view text;
    if (command != nullptr)
    {
        text = command;
    }

    if (!text.starts_with("/zonetrace"))
    {
        return false;
    }

    if (core_ != nullptr && core_->GetChatManager() != nullptr)
    {
        core_->GetChatManager()->Writef(0, false, "\x1E\x51[zonetrace]\x1E\x01 logging to %s", log_.path().c_str());
    }

    return true;
}

void ZoneTrace::identify()
{
    const auto connection = sockets::connections();
    if (core_ == nullptr || connection == loggedConnection_)
    {
        return;
    }

    if (connection != seenConnection_)
    {
        seenConnection_ = connection;
        seenAt_         = Clock::now();
    }

    const auto identity = readIdentity(core_);
    if (!identity)
    {
        // answered but no character loaded
        if (connection != warnedConnection_ && Clock::now() - seenAt_ > kNoCharacterWarning)
        {
            warnedConnection_ = connection;
            emit(&write, "char", "zone-in answered 15 s ago but no character loaded");
            recv::report();
        }

        return;
    }

    // the zone id updates a moment after the server answers; entering a mog house never changes it
    if (identity->zone == lastZone_ && Clock::now() - seenAt_ < kZoneSettle)
    {
        return;
    }

    lastZone_         = identity->zone;
    loggedConnection_ = connection;

    emit(&write, "char", "{} (charid {}) in zone {}", identity->name.data(), identity->id, identity->zone);
}

} // namespace zonetrace

extern "C" __declspec(dllexport) IPolPlugin* __stdcall expCreatePolPlugin(const char* args)
{
    UNREFERENCED_PARAMETER(args);
    return new zonetrace::ZoneTrace();
}

extern "C" __declspec(dllexport) void __stdcall expDestroyPlugin(void* instance)
{
    delete static_cast<zonetrace::ZoneTrace*>(instance);
}

extern "C" __declspec(dllexport) double __stdcall expGetInterfaceVersion(void)
{
    return ASHITA_INTERFACE_VERSION;
}
