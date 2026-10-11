#pragma once

#include <cstdint>

namespace zonetrace
{

enum class Attempt : uint8_t
{
    NoModule, // not loaded yet, keep waiting
    NotFound, // loaded but nothing to hook yet, or hooked by another plugin
    Hooked,
};

} // namespace zonetrace
