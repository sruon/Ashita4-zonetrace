#include "sockets.hpp"

#include "log.hpp"
#include "memory.hpp"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <cstdio>
#include <map>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

namespace zonetrace::sockets
{
    namespace
    {
        using BindFunction     = int(WSAAPI*)(SOCKET, const sockaddr*, int);
        using SendToFunction   = int(WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
        using RecvFromFunction = int(WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
        using CloseFunction    = int(WSAAPI*)(SOCKET);

        // the server normally answers every packet; this long without one means the connection is dying
        constexpr ULONGLONG kSilence = 5000;

        struct Socket
        {
            uint16_t port{};
            std::string peer;
            ULONGLONG opened{};
            ULONGLONG lastReceive{};
            uint32_t sent{};
            uint32_t received{};
            int lastError{};
            bool silent{};
        };

        LineSink sink_{};
        BindFunction realBind{};
        SendToFunction realSendTo{};
        RecvFromFunction realRecvFrom{};
        CloseFunction realClose{};

        std::mutex mutex_;
        std::map<SOCKET, Socket> sockets_;

        template <typename... Args>
        void emit(const char* pattern, Args... args)
        {
            char buffer[256];
            snprintf(buffer, sizeof(buffer), pattern, args...);
            if (sink_ != nullptr)
                sink_(timestamp() + " socket " + buffer);
        }

        auto address(const sockaddr* name) -> std::string
        {
            if (name == nullptr || name->sa_family != AF_INET)
                return "?";

            const auto in = reinterpret_cast<const sockaddr_in*>(name);
            char text[32]{};
            inet_ntop(AF_INET, &in->sin_addr, text, sizeof(text));

            char out[48];
            snprintf(out, sizeof(out), "%s:%u", text, ntohs(in->sin_port));
            return out;
        }

        auto seconds(ULONGLONG from, ULONGLONG to) -> double
        {
            return static_cast<double>(to - from) / 1000.0;
        }

        int WSAAPI hookedBind(SOCKET socket, const sockaddr* name, int length)
        {
            const auto result = realBind(socket, name, length);
            const auto error  = result == SOCKET_ERROR ? WSAGetLastError() : 0;

            const uint16_t port = name != nullptr && name->sa_family == AF_INET ? ntohs(reinterpret_cast<const sockaddr_in*>(name)->sin_port) : uint16_t{};
            if (result == 0)
            {
                std::lock_guard lock(mutex_);

                Socket entry;
                entry.port       = port;
                entry.opened     = ::GetTickCount64();
                sockets_[socket] = entry;
                emit("bound local port %u", port);
            }
            else
            {
                // FFXiMain retries at +256 when the port is taken
                emit("local port %u is taken (error %d)", port, error);
            }

            if (error != 0)
                WSASetLastError(error);
            return result;
        }

        int WSAAPI hookedSendTo(SOCKET socket, const char* buffer, int length, int flags, const sockaddr* to, int toLength)
        {
            {
                std::lock_guard lock(mutex_);
                if (const auto it = sockets_.find(socket); it != sockets_.end())
                {
                    auto& entry    = it->second;
                    const auto now = ::GetTickCount64();

                    if (const auto peer = address(to); entry.peer != peer)
                    {
                        entry.peer = peer;
                        emit("port %u connecting to %s", entry.port, peer.c_str());
                    }

                    ++entry.sent;

                    // before the first answer the game only repeats its zone-in request
                    if (entry.received != 0 && !entry.silent && now - entry.lastReceive > kSilence)
                    {
                        entry.silent = true;
                        emit("port %u: nothing from %s for %.1f s, still sending", entry.port, entry.peer.c_str(), seconds(entry.lastReceive, now));
                    }
                }
            }

            return realSendTo(socket, buffer, length, flags, to, toLength);
        }

        int WSAAPI hookedRecvFrom(SOCKET socket, char* buffer, int length, int flags, sockaddr* from, int* fromLength)
        {
            const auto result = realRecvFrom(socket, buffer, length, flags, from, fromLength);
            const auto error  = result == SOCKET_ERROR ? WSAGetLastError() : 0;

            {
                std::lock_guard lock(mutex_);
                if (const auto it = sockets_.find(socket); it != sockets_.end())
                {
                    auto& entry    = it->second;
                    const auto now = ::GetTickCount64();

                    if (result > 0)
                    {
                        if (entry.received == 0)
                            emit("port %u: zone-in answered after %.1f s and %u requests", entry.port, seconds(entry.opened, now), entry.sent);
                        else if (entry.silent)
                            emit("port %u: server is answering again after %.1f s", entry.port, seconds(entry.lastReceive, now));

                        ++entry.received;
                        entry.lastReceive = now;
                        entry.silent      = false;
                    }
                    else if (error != 0 && error != WSAEWOULDBLOCK && error != entry.lastError)
                    {
                        // 10054 here means an ICMP port unreachable came back for something the game sent
                        entry.lastError = error;
                        emit("port %u: receive error %d", entry.port, error);
                    }
                }
            }

            if (error != 0)
                WSASetLastError(error);
            return result;
        }

        int WSAAPI hookedClose(SOCKET socket)
        {
            {
                std::lock_guard lock(mutex_);
                if (const auto it = sockets_.find(socket); it != sockets_.end())
                {
                    const auto& entry = it->second;
                    const auto now    = ::GetTickCount64();

                    if (entry.received == 0 && entry.sent != 0)
                        emit("port %u: BLACK SCREEN, %s never answered %u zone-in requests in %.1f s", entry.port, entry.peer.c_str(), entry.sent, seconds(entry.opened, now));
                    else if (entry.silent)
                        emit("port %u: DISCONNECT, %s stopped answering %.1f s before the game gave up", entry.port, entry.peer.c_str(), seconds(entry.lastReceive, now));

                    emit("closed port %u to %s after %.1f s, sent %u, received %u", entry.port, entry.peer.c_str(), seconds(entry.opened, now), entry.sent, entry.received);
                    sockets_.erase(it);
                }
            }

            return realClose(socket);
        }
    } // namespace

    auto install(LineSink sink) -> Attempt
    {
        const auto game = reinterpret_cast<uintptr_t>(::GetModuleHandleA("FFXiMain.dll"));
        const auto ws2  = ::GetModuleHandleA("ws2_32.dll");
        if (game == 0 || ws2 == nullptr)
            return Attempt::NoModule;

        sink_        = sink;
        realBind     = reinterpret_cast<BindFunction>(::GetProcAddress(ws2, "bind"));
        realSendTo   = reinterpret_cast<SendToFunction>(::GetProcAddress(ws2, "sendto"));
        realRecvFrom = reinterpret_cast<RecvFromFunction>(::GetProcAddress(ws2, "recvfrom"));
        realClose    = reinterpret_cast<CloseFunction>(::GetProcAddress(ws2, "closesocket"));

        int patched = 0;
        patched += memory::patchSlots(game, reinterpret_cast<uintptr_t>(realBind), reinterpret_cast<uintptr_t>(&hookedBind));
        patched += memory::patchSlots(game, reinterpret_cast<uintptr_t>(realSendTo), reinterpret_cast<uintptr_t>(&hookedSendTo));
        patched += memory::patchSlots(game, reinterpret_cast<uintptr_t>(realRecvFrom), reinterpret_cast<uintptr_t>(&hookedRecvFrom));
        patched += memory::patchSlots(game, reinterpret_cast<uintptr_t>(realClose), reinterpret_cast<uintptr_t>(&hookedClose));
        if (patched == 0)
            return Attempt::NotFound;

        emit("hooked FFXiMain.dll (%d import slots)", patched);
        return Attempt::Hooked;
    }
} // namespace zonetrace::sockets
