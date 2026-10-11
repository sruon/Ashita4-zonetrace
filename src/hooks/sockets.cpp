#include "hooks/sockets.h"

#include "common/memory.h"

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <ranges>

#pragma comment(lib, "ws2_32.lib")

namespace zonetrace::sockets
{
namespace
{

using namespace std::chrono_literals;

using Clock            = std::chrono::steady_clock;
using BindFunction     = int(WSAAPI*)(SOCKET, const sockaddr*, int);
using SendToFunction   = int(WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
using RecvFromFunction = int(WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
using CloseFunction    = int(WSAAPI*)(SOCKET);

constexpr std::string_view kSource     = "socket";
constexpr auto             kSilence    = 5s;  // the server normally answers every packet; this long without one means the connection is dying
constexpr auto             kUnanswered = 10s; // a zone-in normally answers within 5 s; reported while still waiting so a killed client keeps the line

struct Socket
{
    uint16_t          port{};
    std::string       peer;
    Clock::time_point opened;
    Clock::time_point lastReceive;
    Clock::time_point lastSend;
    uint32_t          sent{};
    uint32_t          received{};
    int               lastError{};
    std::string       stray; // last sender that was not the server this socket talks to
    bool              silent{};
    bool              quiet{};
    bool              unanswered{};
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

auto address(const sockaddr* name) -> std::string
{
    if (name == nullptr || name->sa_family != AF_INET)
    {
        return "?";
    }

    const auto           in = reinterpret_cast<const sockaddr_in*>(name);
    std::array<char, 32> text{};
    inet_ntop(AF_INET, &in->sin_addr, text.data(), text.size());

    return std::format("{}:{}", text.data(), ntohs(in->sin_port));
}

auto seconds(Clock::duration elapsed) -> double
{
    return std::chrono::duration<double>(elapsed).count();
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

        sockets_[socket] = { .port = port, .opened = Clock::now() };
        emit(sink_, kSource, "bound local port {}", port);

        // a server that ties the session to the client's address will not recognise the new one
        if (lastPort_ != 0 && lastPort_ != port)
        {
            emit(sink_, kSource, "LOCAL PORT CHANGED {} -> {} since the previous zone", lastPort_, port);
        }

        lastPort_ = port;
    }
    else
    {
        // FFXiMain retries at +256 when the port is taken
        emit(sink_, kSource, "local port {} is taken (error {})", port, error);
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
            const auto now   = Clock::now();

            if (const auto peer = address(to); entry.peer != peer)
            {
                entry.peer = peer;
                emit(sink_, kSource, "port {} connecting to {}", entry.port, peer);
            }

            ++entry.sent;

            if (entry.quiet)
            {
                entry.quiet = false;
                emit(sink_, kSource, "port {}: the game is sending again after {:.1f} s", entry.port, seconds(now - entry.lastSend));
            }

            entry.lastSend = now;

            if (entry.received == 0 && !entry.unanswered && now - entry.opened > kUnanswered)
            {
                entry.unanswered = true;
                emit(sink_, kSource, "port {}: BLACK SCREEN so far, {} has not answered {} zone-in requests in {:.1f} s", entry.port, entry.peer, entry.sent, seconds(now - entry.opened));
            }

            // before the first answer the game only repeats its zone-in request
            if (entry.received != 0 && !entry.silent && now - entry.lastReceive > kSilence)
            {
                entry.silent = true;
                emit(sink_, kSource, "port {}: nothing from {} for {:.1f} s, still sending", entry.port, entry.peer, seconds(now - entry.lastReceive));
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
            const auto now   = Clock::now();

            if (result > 0)
            {
                // the game keeps only datagrams from its zone server's IP, whatever the port
                if (const auto source = address(from); from != nullptr && source != entry.peer && source != entry.stray)
                {
                    entry.stray = source;
                    emit(sink_, kSource, "port {}: datagram from {} while talking to {}", entry.port, source, entry.peer);
                }

                if (entry.received == 0)
                {
                    ++connections_;
                    emit(sink_, kSource, "port {}: zone-in answered after {:.1f} s and {} requests", entry.port, seconds(now - entry.opened), entry.sent);
                }
                else if (entry.silent)
                {
                    emit(sink_, kSource, "port {}: server is answering again after {:.1f} s", entry.port, seconds(now - entry.lastReceive));
                }

                ++entry.received;
                entry.lastReceive = now;
                entry.silent      = false;
            }
            else if (error != 0 && error != WSAEWOULDBLOCK && error != entry.lastError)
            {
                // 10054 here means an ICMP port unreachable came back for something the game sent
                entry.lastError = error;
                emit(sink_, kSource, "port {}: receive error {}", entry.port, error);
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
            const auto  now   = Clock::now();

            if (entry.received == 0 && entry.sent != 0)
            {
                emit(sink_, kSource, "port {}: BLACK SCREEN, {} never answered {} zone-in requests in {:.1f} s", entry.port, entry.peer, entry.sent, seconds(now - entry.opened));
            }
            else if (entry.silent)
            {
                emit(sink_, kSource, "port {}: DISCONNECT, {} stopped answering {:.1f} s before the game gave up", entry.port, entry.peer, seconds(now - entry.lastReceive));
            }

            emit(sink_, kSource, "closed port {} to {} after {:.1f} s, sent {}, received {}", entry.port, entry.peer, seconds(now - entry.opened), entry.sent, entry.received);
            sockets_.erase(it);
        }
    }

    return realClose_(socket);
}

} // namespace

void poll()
{
    std::lock_guard lock(mutex_);
    const auto      now = Clock::now();
    for (auto& entry : sockets_ | std::views::values)
    {
        // in game it sends a few packets a second, so a pause means the client stalled or gave up
        if (entry.sent != 0 && !entry.quiet && now - entry.lastSend > kSilence)
        {
            entry.quiet = true;
            emit(sink_, kSource, "port {}: the game has not sent anything for {:.1f} s (sent {}, received {})", entry.port, seconds(now - entry.lastSend), entry.sent, entry.received);
        }
    }
}

auto connections() -> uint32_t
{
    return connections_;
}

auto install(LineSink sink) -> Attempt
{
    const auto game = memory::moduleBase("FFXiMain.dll");
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

    emit(sink_, kSource, "hooked FFXiMain.dll ({} import slots)", patched);
    return Attempt::Hooked;
}

} // namespace zonetrace::sockets
