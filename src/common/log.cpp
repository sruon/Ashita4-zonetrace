#include "common/log.h"

#include <Windows.h>

#include <format>
#include <share.h>

namespace zonetrace
{

auto timestamp() -> std::string
{
    SYSTEMTIME now{};
    ::GetLocalTime(&now);

    return std::format("{:02}:{:02}:{:02}.{:03}", now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
}

auto Log::open(const std::string& directory) -> bool
{
    std::lock_guard lock(mutex_);

    ::CreateDirectoryA(directory.c_str(), nullptr);

    SYSTEMTIME now{};
    ::GetLocalTime(&now);

    path_ = std::format("{}\\zonetrace_{:04}{:02}{:02}_{:02}{:02}{:02}_{}.log", directory, now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, ::GetCurrentProcessId());

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
    {
        return;
    }

    fputs(text.c_str(), file_);
    fputc('\n', file_);
    fflush(file_);
}

auto Log::path() const -> const std::string&
{
    return path_;
}

} // namespace zonetrace
