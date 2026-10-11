#pragma once

#include <cstdio>
#include <mutex>
#include <string>

namespace zonetrace
{

// one log file per process; every line is flushed so a crash keeps everything up to it
class Log
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

} // namespace zonetrace
