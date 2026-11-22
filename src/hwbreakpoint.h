// hwbreakpoint.h — hardware breakpoint manager (DR0..DR3 + DR7)
//
// The x86-64 CPU exposes four debug address registers (DR0..DR3) plus a
// control register (DR7). Each slot can trigger on execute, write, or
// read+write of a 1/2/4/8-byte region. A hit shows up to the debugger as
// EXCEPTION_SINGLE_STEP; the slot index is reported through DR6 bits B0-B3.
//
// Debug registers are per-thread, so the manager must be applied to every
// thread of the debuggee — and to any newly created thread (we hook
// CREATE_THREAD_DEBUG_EVENT in the engine for that).
#pragma once

#include "common.h"

#include <array>

namespace mdbg {

enum class HwCondition {
    Execute,     // fire before the instruction at `addr` executes
    Write,       // fire after a write touches [addr .. addr+size)
    ReadWrite,   // fire after any access to [addr .. addr+size)
};

enum class HwSize {
    Byte  = 1,
    Word  = 2,
    Dword = 4,
    Qword = 8,
};

using HwBpId = std::uint32_t;

struct HwBreakpoint {
    HwBpId      id{};
    int         slot{-1};        // 0..3 — index into DR0..DR3
    Address     addr{};
    HwCondition cond{HwCondition::Execute};
    HwSize      size{HwSize::Byte};
    bool        active{false};
    std::string label;
};

class HwBreakpointManager {
public:
    // Returns id > 0 on success, or 0 if no free slot / bad alignment.
    HwBpId add(Address addr, HwCondition cond, HwSize size);
    bool   remove(HwBpId id);

    // Snapshot of currently-active HBPs (UI reads this).
    std::vector<HwBreakpoint> list() const;

    // Direct slot access.
    const HwBreakpoint* slot(int i) const;

    // Which slot (0..3) fired, inferred from DR6; -1 if none.
    static int firedSlot(std::uint64_t dr6);

    bool isExecuteSlot(int slot) const;

    // Push the current slot state onto one thread's debug registers.
    // The thread must be suspended (true for all threads during a debug
    // break, and for the hThread of CREATE_THREAD_DEBUG_EVENT).
    bool applyToThread(HANDLE thread) const;
    void applyToAll(const std::map<DWORD, HANDLE>& threads) const;

private:
    std::uint64_t computeDr7() const;

    std::array<HwBreakpoint, 4> m_slots{};
    HwBpId                      m_nextId{1};
};

} // namespace mdbg
