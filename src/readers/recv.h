#pragma once

#include "common/log.h"
#include "enums/attempt.h"

namespace zonetrace::recv // the game counts the datagrams and sub-packets it drops, per reason, on its zone object
{

auto install(LineSink sink) -> Attempt;
void poll();   // logs drops whenever a counter moves
void report(); // logs the counters and sequences as they are now

} // namespace zonetrace::recv
