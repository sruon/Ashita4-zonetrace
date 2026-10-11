#include "plugin.hpp"

#include "key.hpp"
#include "log.hpp"
#include "memory.hpp"
#include "port.hpp"
#include "recv.hpp"
#include "sockets.hpp"

#include <cstdlib>
#include <format>
#include <string_view>

namespace zonetrace
{
namespace
{

Log log_;

void write(const std::string& line)
{
    log_.line(line);
}

// the directory this dll lives in; the plugin id is its module base
auto moduleDirectory(uint32_t id) -> std::string
{
    char path[MAX_PATH]{};
    ::GetModuleFileNameA(reinterpret_cast<HMODULE>(static_cast<uintptr_t>(id)), path, MAX_PATH);

    std::string directory(path);
    if (const auto slash = directory.find_last_of("\\/"); slash != std::string::npos)
    {
        directory.resize(slash);
    }

    return directory;
}

struct Identity
{
    uint32_t id;
    uint16_t zone;
    char     name[24];
};

// reads the player's own party slot. guarded: the game rewrites this memory while zoning
auto readIdentity(IAshitaCore* core, Identity* identity) -> bool
{
    __try
    {
        const auto memory = core->GetMemoryManager();
        if (memory == nullptr)
        {
            return false;
        }

        const auto party = memory->GetParty();
        if (party == nullptr || party->GetMemberIsActive(0) == 0)
        {
            return false;
        }

        const auto name = party->GetMemberName(0);
        if (name == nullptr)
        {
            return false;
        }

        identity->id   = party->GetMemberServerId(0);
        identity->zone = party->GetMemberZone(0);
        for (size_t i = 0; i + 1 < sizeof(identity->name) && name[i] >= 0x20 && name[i] < 0x7F; ++i)
        {
            identity->name[i] = name[i];
        }

        return identity->id != 0 && identity->name[0] != 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
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

    char name[64]{};
    ::WideCharToMultiByte(CP_ACP, 0, zoneName, -1, name, sizeof(name) - 1, nullptr, nullptr);

    char sign = '+';
    if (offset < 0)
    {
        sign = '-';
    }

    return std::format("{:04}-{:02}-{:02}, all times are local: UTC{}{:02}:{:02} ({})", local.wYear, local.wMonth, local.wDay, sign, abs(offset) / 60, abs(offset) % 60, static_cast<const char*>(name));
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
    return 1.2;
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

    log_.line(timestamp() + " zonetrace 1.2, " + clock());

    // POL plugins load before polcore and the game; both unpack themselves, so keep trying until the hooks take
    stop_    = false;
    watcher_ = std::thread(
        [this]
        {
            // give up on a module that still has nothing to hook after this many tries
            constexpr int kAttempts = 500;

            int  portMisses    = 0;
            int  socketMisses  = 0;
            int  keyMisses     = 0;
            int  counterMisses = 0;
            int  recvMisses    = 0;
            bool ports         = false;
            bool sockets       = false;
            bool keys          = false;
            bool counters      = false;
            bool recvs         = false;
            while (!stop_)
            {
                if (!ports && portMisses < kAttempts)
                {
                    const auto attempt = port::install(&write);
                    ports              = attempt == Attempt::Hooked;
                    if (attempt == Attempt::NotFound && ++portMisses == kAttempts)
                    {
                        log_.line(timestamp() + " port   cannot find polcore's port chooser: client updated, or another plugin already hooked it");
                    }
                }

                if (!sockets && socketMisses < kAttempts)
                {
                    const auto attempt = sockets::install(&write);
                    sockets            = attempt == Attempt::Hooked;
                    if (attempt == Attempt::NotFound && ++socketMisses == kAttempts)
                    {
                        log_.line(timestamp() + " socket cannot hook the game's sockets: another plugin already hooked them");
                    }
                }

                if (!keys && keyMisses < kAttempts)
                {
                    const auto attempt = key::install(&write);
                    keys               = attempt == Attempt::Hooked;
                    if (attempt == Attempt::NotFound && ++keyMisses == kAttempts)
                    {
                        log_.line(timestamp() + " key    cannot find polcore's session key value: client updated");
                    }
                }

                if (!counters && counterMisses < kAttempts)
                {
                    const auto attempt = key::installCounter(&write);
                    counters           = attempt == Attempt::Hooked;
                    if (attempt == Attempt::NotFound && ++counterMisses == kAttempts)
                    {
                        log_.line(timestamp() + " key    cannot find FFXiMain's zone key counter: client updated");
                    }
                }

                if (!recvs && recvMisses < kAttempts)
                {
                    const auto attempt = recv::install(&write);
                    recvs              = attempt == Attempt::Hooked;
                    if (attempt == Attempt::NotFound && ++recvMisses == kAttempts)
                    {
                        log_.line(timestamp() + " recv   cannot find FFXiMain's zone object: client updated");
                    }
                }

                port::poll();
                key::poll();
                recv::poll();
                sockets::poll();
                identify();

                const auto waiting = (!ports && portMisses < kAttempts) || (!sockets && socketMisses < kAttempts) || (!keys && keyMisses < kAttempts) || (!counters && counterMisses < kAttempts) || (!recvs && recvMisses < kAttempts);
                auto       delay   = std::chrono::milliseconds(500);
                if (waiting)
                {
                    delay = std::chrono::milliseconds(20);
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
    log_.line(timestamp() + " zonetrace unloaded");
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

    text.remove_prefix(10);
    while (text.starts_with(' '))
    {
        text.remove_prefix(1);
    }

    // "/zonetrace mark stuck in jeuno" labels the moment in the log
    if (text.starts_with("mark"))
    {
        text.remove_prefix(4);
        while (text.starts_with(' '))
        {
            text.remove_prefix(1);
        }

        log_.line(timestamp() + " ===== MARK " + std::string(text) + " =====");
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
        seenAt_         = ::GetTickCount64();
    }

    Identity identity{};
    if (!readIdentity(core_, &identity))
    {
        // answered but no character loaded
        if (connection != warnedConnection_ && ::GetTickCount64() - seenAt_ > 15000)
        {
            warnedConnection_ = connection;
            log_.line(timestamp() + " char   zone-in answered 15 s ago but no character loaded");
            recv::report();
        }

        return;
    }

    // the zone id updates a moment after the server answers; entering a mog house never changes it
    if (identity.zone == lastZone_ && ::GetTickCount64() - seenAt_ < 2000)
    {
        return;
    }

    lastZone_         = identity.zone;
    loggedConnection_ = connection;

    log_.line(std::format("{} char   {} (charid {}) in zone {}", timestamp(), static_cast<const char*>(identity.name), identity.id, identity.zone));
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
