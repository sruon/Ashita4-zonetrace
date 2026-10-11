#pragma once

#include "common/log.h"
#include "enums/attempt.h"

namespace zonetrace::key // zone key = MD5(16-byte value from polcore || lobby counter). only a hash of the value is logged
{

auto install(LineSink sink) -> Attempt;
auto installCounter(LineSink sink) -> Attempt;
void poll(); // logs the value's fingerprint and the counter whenever they change

} // namespace zonetrace::key
