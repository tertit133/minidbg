// breakpoint.h — soft breakpoint manager (INT3 / 0xCC)
#pragma once

#include "common.h"

namespace mdbg {

using BreakpointId = std::uint32_t;

struct Breakpoint {
    BreakpointId id{};
    Address      address{};
    Byte         originalByte{};
    bool         enabled{true};
    bool         oneShot{false};
    std::string  label;
    // Optional Lua expression evaluated on hit. If it evaluates to false,
    // the hit is skipped silently (BP re-arms and execution continues).
    // Empty string means "always pause", i.e. a plain BP.
    std::string  script;
};

class BreakpointManager {
public:
    // Place a BP at `addr` in `process`. If one already exists, returns that id.
    BreakpointId add(HANDLE process, Address addr);

    // Remove by id. Restores the original byte if the BP was enabled.
    bool remove(HANDLE process, BreakpointId id);

    bool enable(HANDLE process, BreakpointId id, bool on);

    const std::vector<Breakpoint>& list() const { return m_bps; }

    Breakpoint* find(Address addr);
    const Breakpoint* find(Address addr) const;

    // Restore the original byte at `addr` without removing the BP record —
    // used after a hit so the original instruction can execute.
    bool restoreOriginal(HANDLE process, Address addr);

    // Re-write 0xCC at `addr` (only if the BP is still enabled).
    bool arm(HANDLE process, Address addr);

private:
    std::vector<Breakpoint> m_bps;
    BreakpointId            m_next{1};
};

} // namespace mdbg
