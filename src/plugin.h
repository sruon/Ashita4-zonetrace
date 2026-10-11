#pragma once

#include "Ashita.h"

#include <atomic>
#include <chrono>
#include <thread>

namespace zonetrace
{

class ZoneTrace final : public IPolPlugin
{
public:
    const char* GetName(void) const override;
    const char* GetAuthor(void) const override;
    const char* GetDescription(void) const override;
    const char* GetLink(void) const override;
    double      GetVersion(void) const override;
    uint32_t    GetFlags(void) const override;
    bool        Initialize(IAshitaCore* core, ILogManager* logger, uint32_t id) override;
    void        Release(void) override;
    bool        HandleCommand(int32_t mode, const char* command, bool injected) override;

private:
    void identify(); // names the character once per zone connection, so the log can be matched to the server's by charid

    uint32_t                              loggedConnection_{};
    uint32_t                              warnedConnection_{};
    uint32_t                              seenConnection_{};
    std::chrono::steady_clock::time_point seenAt_;
    uint16_t                              lastZone_{};
    IAshitaCore*                          core_{};
    std::atomic<bool>                     stop_{};
    std::thread                           watcher_;
};

} // namespace zonetrace
