#pragma once

#include <cstdio>
#include <format>
#include <mutex>
#include <string>
#include <string_view>

namespace zonetrace
{

using LineSink = void (*)(const std::string& line);

class Log // one file per process, flushed on every line
{
public:
    auto open(const std::string& directory) -> bool;
    void close();
    void line(const std::string& text);
    auto path() const -> const std::string&;

private:
    std::mutex  mutex_;
    FILE*       file_{};
    std::string path_;
};

auto timestamp() -> std::string;

template <typename... Args>
void emit(LineSink sink, std::string_view source, std::format_string<Args...> format, Args&&... args)
{
    if (sink != nullptr)
    {
        sink(std::format("{} {:<6} {}", timestamp(), source, std::format(format, std::forward<Args>(args)...)));
    }
}

} // namespace zonetrace
