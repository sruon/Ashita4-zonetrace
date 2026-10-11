#pragma once

#include "port.hpp"

namespace zonetrace
{

// follows the game's UDP sockets: one per zone connection, closed and reopened on every zone change.
// nothing of the traffic itself is logged, only addresses, counts and timings
namespace sockets
{

// hooks bind, sendto, recvfrom and closesocket in FFXiMain's import table
auto install(LineSink sink) -> Attempt;

// reports sockets the game has stopped sending on
void poll();

// how many zone connections the server has answered so far
auto connections() -> uint32_t;

} // namespace sockets
} // namespace zonetrace
