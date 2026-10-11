#pragma once

#include "port.hpp"

namespace zonetrace
{

// zone key = MD5(16-byte value from polcore || lobby counter). only a hash of the value is logged
namespace key
{

// the getter FFXiMain calls: mov eax,[esp+4]; push 16; push <value>; push eax; call memcpy; add esp,12; ret
constexpr uint8_t pattern[] = { 0x8B, 0x44, 0x24, 0x04, 0x6A, 0x10, 0x68, 0, 0, 0, 0, 0x50, 0xE8, 0, 0, 0, 0, 0x83, 0xC4, 0x0C, 0xC3 };
constexpr char    mask[]    = "xxxxxxx????xx????xxxx";

// FNV-1a over the 16 bytes; a server admin computes the same from the first 16 bytes of accounts_sessions.session_key
inline auto fingerprint(const uint8_t* value) -> uint32_t
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < 16; ++i)
    {
        hash = (hash ^ value[i]) * 16777619u;
    }

    return hash;
}

// the lobby counter, +2 per zone connect. found through the zone connect step that loads the main system struct:
//   mov eax,[pGcMainSys]; mov dword [eax+136ACh],0; mov eax,[dllsw]; test eax,eax; jnz +35h; call
constexpr uint8_t counterPattern[] = { 0xA1, 0, 0, 0, 0, 0xC7, 0x80, 0xAC, 0x36, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA1, 0, 0, 0, 0, 0x85, 0xC0, 0x75, 0x35, 0xE8 };
constexpr char    counterMask[]    = "x????xxxxxxxxxxx????xxxxx";

// lobby work copy at +0x136DC, counter at +0x138 into it
constexpr uintptr_t kCounterOffset = 0x136DC + 0x138;

auto install(LineSink sink) -> Attempt;
auto installCounter(LineSink sink) -> Attempt;
void poll(); // logs the value's fingerprint and the counter whenever they change

} // namespace key
} // namespace zonetrace
