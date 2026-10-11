#pragma once

#include "common/log.h"
#include "enums/attempt.h"

namespace zonetrace::port // polcore's choice of the game's local UDP port
{

auto install(LineSink sink) -> Attempt;
void poll(); // logs when the viewer or the server changes the port choice
void remove();

} // namespace zonetrace::port
