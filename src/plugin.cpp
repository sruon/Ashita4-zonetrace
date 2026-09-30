#include "log.hpp"
#include "memory.hpp"
#include "port.hpp"
#include "sockets.hpp"

#include "Ashita.h"

#include <atomic>
#include <string_view>
#include <thread>

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
                directory.resize(slash);
            return directory;
        }

        // server logs are usually in UTC, the lines here are local time
        auto clock() -> std::string
        {
            SYSTEMTIME local{};
            SYSTEMTIME utc{};
            ::GetLocalTime(&local);
            ::GetSystemTime(&utc);

            char buffer[96];
            snprintf(buffer, sizeof(buffer), "%04u-%02u-%02u, local %02u:%02u:%02u is UTC %02u:%02u:%02u", local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond, utc.wHour, utc.wMinute, utc.wSecond);
            return buffer;
        }
    } // namespace

    class ZoneTrace final : public IPolPlugin
    {
    public:
        const char* GetName(void) const override
        {
            return "zonetrace";
        }

        const char* GetAuthor(void) const override
        {
            return "sruon";
        }

        const char* GetDescription(void) const override
        {
            return "Logs which UDP port the game uses for each zone and whether the server answers, to diagnose black screens and disconnects.";
        }

        const char* GetLink(void) const override
        {
            return "";
        }

        double GetVersion(void) const override
        {
            return 1.0;
        }

        uint32_t GetFlags(void) const override
        {
            return static_cast<uint32_t>(Ashita::PluginFlags::UseCommands);
        }

        bool Initialize(IAshitaCore* core, ILogManager* logger, uint32_t id) override
        {
            core_ = core;

            const auto directory = moduleDirectory(id) + "\\logs";
            if (!log_.open(directory))
            {
                if (logger != nullptr)
                    logger->Logf(static_cast<uint32_t>(Ashita::LogLevel::Error), "zonetrace", "cannot open a log in %s", directory.c_str());
                return false;
            }

            log_.line(timestamp() + " zonetrace 1.0, " + clock());

            // POL plugins load before polcore and the game; both unpack themselves, so keep trying until the hooks take
            stop_    = false;
            watcher_ = std::thread([this] {
                // a module that is loaded but offers nothing to hook for this long is not going to
                constexpr int kAttempts = 500;

                int portMisses   = 0;
                int socketMisses = 0;
                bool ports       = false;
                bool sockets     = false;
                while (!stop_)
                {
                    if (!ports && portMisses < kAttempts)
                    {
                        const auto attempt = port::install(&write);
                        ports              = attempt == Attempt::Hooked;
                        if (attempt == Attempt::NotFound && ++portMisses == kAttempts)
                            log_.line(timestamp() + " port   cannot find polcore's port chooser: client updated, or another plugin (polsniff) already hooked it");
                    }

                    if (!sockets && socketMisses < kAttempts)
                    {
                        const auto attempt = sockets::install(&write);
                        sockets            = attempt == Attempt::Hooked;
                        if (attempt == Attempt::NotFound && ++socketMisses == kAttempts)
                            log_.line(timestamp() + " socket cannot hook the game's sockets: another plugin (polsniff) already hooked them");
                    }

                    port::poll();

                    const auto waiting = (!ports && portMisses < kAttempts) || (!sockets && socketMisses < kAttempts);
                    std::this_thread::sleep_for(std::chrono::milliseconds(waiting ? 20 : 500));
                }
            });

            return true;
        }

        void Release(void) override
        {
            stop_ = true;
            if (watcher_.joinable())
                watcher_.join();

            port::remove();
            memory::restoreSlots();
            log_.line(timestamp() + " zonetrace unloaded");
            log_.close();
        }

        bool HandleCommand(int32_t mode, const char* command, bool injected) override
        {
            UNREFERENCED_PARAMETER(mode);
            UNREFERENCED_PARAMETER(injected);

            std::string_view text(command != nullptr ? command : "");
            if (!text.starts_with("/zonetrace"))
                return false;

            text.remove_prefix(10);
            while (text.starts_with(' '))
                text.remove_prefix(1);

            // "/zonetrace mark stuck in jeuno" labels the moment in the log
            if (text.starts_with("mark"))
            {
                text.remove_prefix(4);
                while (text.starts_with(' '))
                    text.remove_prefix(1);

                log_.line(timestamp() + " ===== MARK " + std::string(text) + " =====");
            }

            if (core_ != nullptr && core_->GetChatManager() != nullptr)
                core_->GetChatManager()->Writef(0, false, "\x1E\x51[zonetrace]\x1E\x01 logging to %s", log_.path().c_str());
            return true;
        }

    private:
        IAshitaCore* core_{};
        std::atomic<bool> stop_{};
        std::thread watcher_;
    };
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
