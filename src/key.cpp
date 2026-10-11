#include "key.hpp"

#include "log.hpp"
#include "memory.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstdio>

namespace zonetrace::key
{
    namespace
    {
        LineSink sink_{};
        const uint8_t* value_{};
        uint8_t last_[16]{};
        bool logged_{};

        const uintptr_t* mainSystem_{};
        uint32_t lastCounter_{};

        void emit(const char* text)
        {
            if (sink_ != nullptr)
                sink_(timestamp() + " key    " + text);
        }

        // guarded: the struct is allocated at login and freed on logout
        auto counter() -> uint32_t
        {
            __try
            {
                const auto system = *mainSystem_;
                return system != 0 ? *reinterpret_cast<const uint32_t*>(system + kCounterOffset) : 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 0;
            }
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

            uintptr_t value{};
            std::memcpy(&value, reinterpret_cast<const uint8_t*>(address) + 7, sizeof(uint32_t));

            sink_  = sink;
            value_ = reinterpret_cast<const uint8_t*>(value);

            char buffer[96];
            snprintf(buffer, sizeof(buffer), "found the session key value in %s at +0x%X", name, static_cast<unsigned>(value - base));
            emit(buffer);
            poll();
            return Attempt::Hooked;
        }

        return Attempt::NoModule;
    }

    auto installCounter(LineSink sink) -> Attempt
    {
        const auto base = reinterpret_cast<uintptr_t>(::GetModuleHandleA("FFXiMain.dll"));
        if (base == 0)
            return Attempt::NoModule;

        const auto address = memory::findPattern(base, memory::imageSize(base), counterPattern, counterMask);
        if (address == 0)
            return Attempt::NotFound;

        uintptr_t global{};
        std::memcpy(&global, reinterpret_cast<const uint8_t*>(address) + 1, sizeof(uint32_t));

        sink_       = sink;
        mainSystem_ = reinterpret_cast<const uintptr_t*>(global);
        return Attempt::Hooked;
    }

    void poll()
    {
        // the counter alone is not secret
        if (mainSystem_ != nullptr)
        {
            if (const auto current = counter(); current != 0 && current != lastCounter_)
            {
                char buffer[96];
                snprintf(buffer, sizeof(buffer), "zone key counter %08X (%+d)", current, lastCounter_ != 0 ? static_cast<int>(current - lastCounter_) : 0);
                emit(buffer);
                lastCounter_ = current;
            }
        }

        if (value_ == nullptr)
            return;

        uint8_t current[16];
        std::memcpy(current, value_, sizeof(current));
        if (logged_ && std::equal(current, current + 16, last_))
            return;

        std::memcpy(last_, current, sizeof(last_));
        logged_ = true;

        char buffer[128];
        if (std::all_of(current, current + 16, [](uint8_t byte) { return byte == 0; }))
            snprintf(buffer, sizeof(buffer), "session key value is all zeros (server did not send one yet)");
        else
            snprintf(buffer, sizeof(buffer), "session key value fingerprint %08X", fingerprint(current));
        emit(buffer);
    }
} // namespace zonetrace::key
