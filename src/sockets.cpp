#include "sockets.hpp"

#include "log.hpp"
#include "memory.hpp"

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>

#include <atomic>
#include <format>
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

// a zone-in normally answers within 5 s; reported while still waiting so a killed client keeps the line
constexpr ULONGLONG kUnanswered = 10000;

struct Socket
{
    uint16_t    port{};
    std::string peer;
    ULONGLONG   opened{};
    ULONGLONG   lastReceive{};
    ULONGLONG   lastSend{};
    uint32_t    sent{};
    uint32_t    received{};
    int         lastError{};
    std::string stray; // last sender that was not the server this socket talks to
    bool        silent{};
    bool        quiet{};
    bool        unanswered{};
};

LineSink         sink_{};
BindFunction     realBind_{};
SendToFunction   realSendTo_{};
RecvFromFunction realRecvFrom_{};
CloseFunction    realClose_{};

std::mutex               mutex_;
std::map<SOCKET, Socket> sockets_;
uint16_t                 lastPort_{};
std::atomic<uint32_t>    connections_{};

template <typename... Args>
void emit(std::format_string<Args...> format, Args&&... args)
{
    if (sink_ != nullptr)
    {
        sink_(timestamp() + " socket " + std::format(format, std::forward<Args>(args)...));
    }
}

auto address(const sockaddr* name) -> std::string
{
    if (name == nullptr || name->sa_family != AF_INET)
    {
        return "?";
    }

    const auto in = reinterpret_cast<const sockaddr_in*>(name);
    char       text[32]{};
    inet_ntop(AF_INET, &in->sin_addr, text, sizeof(text));

    return std::format("{}:{}", static_cast<const char*>(text), ntohs(in->sin_port));
}

auto seconds(ULONGLONG from, ULONGLONG to) -> double
{
    return static_cast<double>(to - from) / 1000.0;
}

auto WSAAPI hookedBind(SOCKET socket, const sockaddr* name, int length) -> int
{
    const auto result = realBind_(socket, name, length);
    int        error  = 0;
    if (result == SOCKET_ERROR)
    {
        error = WSAGetLastError();
    }

    uint16_t port{};
    if (name != nullptr && name->sa_family == AF_INET)
    {
        port = ntohs(reinterpret_cast<const sockaddr_in*>(name)->sin_port);
    }

    if (result == 0)
    {
        std::lock_guard lock(mutex_);

        Socket entry;
        entry.port       = port;
        entry.opened     = ::GetTickCount64();
        sockets_[socket] = entry;
        emit("bound local port {}", port);

        // a server that ties the session to the client's address will not recognise the new one
        if (lastPort_ != 0 && lastPort_ != port)
        {
            emit("LOCAL PORT CHANGED {} -> {} since the previous zone", lastPort_, port);
        }

        lastPort_ = port;
    }
    else
    {
        // FFXiMain retries at +256 when the port is taken
        emit("local port {} is taken (error {})", port, error);
    }

    if (error != 0)
    {
        WSASetLastError(error);
    }

    return result;
}

auto WSAAPI hookedSendTo(SOCKET socket, const char* buffer, int length, int flags, const sockaddr* to, int toLength) -> int
{
    {
        std::lock_guard lock(mutex_);
        if (const auto it = sockets_.find(socket); it != sockets_.end())
        {
            auto&      entry = it->second;
            const auto now   = ::GetTickCount64();

            if (const auto peer = address(to); entry.peer != peer)
            {
                entry.peer = peer;
                emit("port {} connecting to {}", entry.port, peer);
            }

            ++entry.sent;

            if (entry.quiet)
            {
                entry.quiet = false;
                emit("port {}: the game is sending again after {:.1f} s", entry.port, seconds(entry.lastSend, now));
            }

            entry.lastSend = now;

            if (entry.received == 0 && !entry.unanswered && now - entry.opened > kUnanswered)
            {
                entry.unanswered = true;
                emit("port {}: BLACK SCREEN so far, {} has not answered {} zone-in requests in {:.1f} s", entry.port, entry.peer, entry.sent, seconds(entry.opened, now));
            }

            // before the first answer the game only repeats its zone-in request
            if (entry.received != 0 && !entry.silent && now - entry.lastReceive > kSilence)
            {
                entry.silent = true;
                emit("port {}: nothing from {} for {:.1f} s, still sending", entry.port, entry.peer, seconds(entry.lastReceive, now));
            }
        }
    }

    return realSendTo_(socket, buffer, length, flags, to, toLength);
}

auto WSAAPI hookedRecvFrom(SOCKET socket, char* buffer, int length, int flags, sockaddr* from, int* fromLength) -> int
{
    const auto result = realRecvFrom_(socket, buffer, length, flags, from, fromLength);
    int        error  = 0;
    if (result == SOCKET_ERROR)
    {
        error = WSAGetLastError();
    }

    {
        std::lock_guard lock(mutex_);
        if (const auto it = sockets_.find(socket); it != sockets_.end())
        {
            auto&      entry = it->second;
            const auto now   = ::GetTickCount64();

            if (result > 0)
            {
                // the game keeps only datagrams from its zone server's IP, whatever the port
                if (const auto source = address(from); from != nullptr && source != entry.peer && source != entry.stray)
                {
                    entry.stray = source;
                    emit("port {}: datagram from {} while talking to {}", entry.port, source, entry.peer);
                }

                if (entry.received == 0)
                {
                    ++connections_;
                    emit("port {}: zone-in answered after {:.1f} s and {} requests", entry.port, seconds(entry.opened, now), entry.sent);
                }
                else if (entry.silent)
                {
                    emit("port {}: server is answering again after {:.1f} s", entry.port, seconds(entry.lastReceive, now));
                }

                ++entry.received;
                entry.lastReceive = now;
                entry.silent      = false;
            }
            else if (error != 0 && error != WSAEWOULDBLOCK && error != entry.lastError)
            {
                // 10054 here means an ICMP port unreachable came back for something the game sent
                entry.lastError = error;
                emit("port {}: receive error {}", entry.port, error);
            }
        }
    }

    if (error != 0)
    {
        WSASetLastError(error);
    }

    return result;
}

auto WSAAPI hookedClose(SOCKET socket) -> int
{
    {
        std::lock_guard lock(mutex_);
        if (const auto it = sockets_.find(socket); it != sockets_.end())
        {
            const auto& entry = it->second;
            const auto  now   = ::GetTickCount64();

            if (entry.received == 0 && entry.sent != 0)
            {
                emit("port {}: BLACK SCREEN, {} never answered {} zone-in requests in {:.1f} s", entry.port, entry.peer, entry.sent, seconds(entry.opened, now));
            }
            else if (entry.silent)
            {
                emit("port {}: DISCONNECT, {} stopped answering {:.1f} s before the game gave up", entry.port, entry.peer, seconds(entry.lastReceive, now));
            }

            emit("closed port {} to {} after {:.1f} s, sent {}, received {}", entry.port, entry.peer, seconds(entry.opened, now), entry.sent, entry.received);
            sockets_.erase(it);
        }
    }

    return realClose_(socket);
}

} // namespace

void poll()
{
    std::lock_guard lock(mutex_);
    const auto      now = ::GetTickCount64();
    for (auto& [socket, entry] : sockets_)
    {
        // in game it sends a few packets a second, so a pause means the client stalled or gave up
        if (entry.sent != 0 && !entry.quiet && now - entry.lastSend > kSilence)
        {
            entry.quiet = true;
            emit("port {}: the game has not sent anything for {:.1f} s (sent {}, received {})", entry.port, seconds(entry.lastSend, now), entry.sent, entry.received);
        }
    }
}

auto connections() -> uint32_t
{
    return connections_;
}

auto install(LineSink sink) -> Attempt
{
    const auto game = reinterpret_cast<uintptr_t>(::GetModuleHandleA("FFXiMain.dll"));
    const auto ws2  = ::GetModuleHandleA("ws2_32.dll");
    if (game == 0 || ws2 == nullptr)
    {
        return Attempt::NoModule;
    }

    sink_         = sink;
    realBind_     = reinterpret_cast<BindFunction>(::GetProcAddress(ws2, "bind"));
    realSendTo_   = reinterpret_cast<SendToFunction>(::GetProcAddress(ws2, "sendto"));
    realRecvFrom_ = reinterpret_cast<RecvFromFunction>(::GetProcAddress(ws2, "recvfrom"));
    realClose_    = reinterpret_cast<CloseFunction>(::GetProcAddress(ws2, "closesocket"));

    int patched = 0;
    patched += memory::patchSlots(game, reinterpret_cast<uintptr_t>(realBind_), reinterpret_cast<uintptr_t>(&hookedBind));
    patched += memory::patchSlots(game, reinterpret_cast<uintptr_t>(realSendTo_), reinterpret_cast<uintptr_t>(&hookedSendTo));
    patched += memory::patchSlots(game, reinterpret_cast<uintptr_t>(realRecvFrom_), reinterpret_cast<uintptr_t>(&hookedRecvFrom));
    patched += memory::patchSlots(game, reinterpret_cast<uintptr_t>(realClose_), reinterpret_cast<uintptr_t>(&hookedClose));
    if (patched == 0)
    {
        return Attempt::NotFound;
    }

    emit("hooked FFXiMain.dll ({} import slots)", patched);
    return Attempt::Hooked;
}

} // namespace zonetrace::sockets
