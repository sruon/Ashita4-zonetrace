#pragma once

#include "port.hpp"

namespace zonetrace
{
    // the game counts the datagrams and sub-packets it drops, per reason, on its zone object
    namespace recv
    {
        // in the receive loop, the source address check against the zone object:
        //   mov edx,[pGlobalNowZone]; mov ecx,[edi+558h]; add esp,4; cmp ecx,[edx+416Ch]
        constexpr uint8_t pattern[] = { 0x8B, 0x15, 0, 0, 0, 0, 0x8B, 0x8F, 0x58, 0x05, 0x00, 0x00, 0x83, 0xC4, 0x04, 0x3B, 0x8A, 0x6C, 0x41, 0x00, 0x00 };
        constexpr char mask[]       = "xx????xxxxxxxxxxxxxxx";

        // the function that counts a drop, its offset into the zone object differs between client builds:
        //   mov eax,[esp+8]; cmp eax,0Ah; jb +5; mov eax,9; mov ecx,[esp+4]; mov edx,[ecx+eax*4+<drops>]; inc edx; mov [ecx+eax*4+<drops>],edx
        constexpr uint8_t dropsPattern[] = { 0x83, 0xF8, 0x0A, 0x72, 0x05, 0xB8, 0x09, 0x00, 0x00, 0x00, 0x8B, 0x4C, 0x24, 0x04, 0x8B, 0x94, 0x81, 0, 0, 0, 0, 0x42, 0x89, 0x94, 0x81 };
        constexpr char dropsMask[]       = "xxxxxxxxxxxxxxxxx????xxxx";

        // zone object fields; the object is zeroed and reused in place on every zone connect
        constexpr uintptr_t kSocket         = 0x00; // the game's socket handle, new on every zone connect
        constexpr uintptr_t kGameSequence   = 0x06; // uint16, the game's own datagram sequence
        constexpr uintptr_t kServerSequence = 0x08; // uint16, the last server datagram sequence the game accepted
        constexpr uintptr_t kServerAck      = 0x0A; // uint16, the server's ack of the game's sequence
        constexpr uintptr_t kState          = 0x0C; // uint8, old datagrams are only dropped in state 3

        auto install(LineSink sink) -> Attempt;
        void poll();   // logs drops whenever a counter moves
        void report(); // logs the counters and sequences as they are now
    } // namespace recv
} // namespace zonetrace
