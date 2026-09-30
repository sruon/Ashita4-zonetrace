#include "log.hpp"

#include <Windows.h>

#include <ctime>
#include <share.h>

namespace zonetrace
{
    auto timestamp() -> std::string
    {
        SYSTEMTIME now{};
        ::GetLocalTime(&now);

        char buffer[32];
        snprintf(buffer, sizeof(buffer), "%02u:%02u:%02u.%03u", now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
        return buffer;
    }

    bool Log::open(const std::string& directory)
    {
        std::lock_guard lock(mutex_);

        ::CreateDirectoryA(directory.c_str(), nullptr);

        SYSTEMTIME now{};
        ::GetLocalTime(&now);

        char name[128];
        snprintf(name, sizeof(name), "\\zonetrace_%04u%02u%02u_%02u%02u%02u_%lu.log", now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, ::GetCurrentProcessId());
        path_ = directory + name;

        // shared, so the log can be read while the game is running
        file_ = _fsopen(path_.c_str(), "ab", _SH_DENYNO);
        return file_ != nullptr;
    }

    void Log::close()
    {
        std::lock_guard lock(mutex_);
        if (file_ != nullptr)
        {
            fclose(file_);
            file_ = nullptr;
        }
    }

    void Log::line(const std::string& text)
    {
        std::lock_guard lock(mutex_);
        if (file_ == nullptr)
            return;

        fputs(text.c_str(), file_);
        fputc('\n', file_);
        fflush(file_);
    }

    auto Log::path() const -> const std::string&
    {
        return path_;
    }
} // namespace zonetrace
