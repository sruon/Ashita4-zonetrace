#pragma once

#include "common/log.h"
#include "enums/attempt.h"

namespace zonetrace::sockets // the game's UDP sockets, one per zone connection
{

auto install(LineSink sink) -> Attempt; // hooks bind, sendto, recvfrom and closesocket in FFXiMain's import table
void poll();                            // reports sockets the game has stopped sending on
auto connections() -> uint32_t;         // how many zone connections the server has answered so far

} // namespace zonetrace::sockets
