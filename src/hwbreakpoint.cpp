#include "hwbreakpoint.h"

namespace mdbg {

namespace {

// Addresses for Word/Dword/Qword HBPs must be naturally aligned.
bool aligned(Address addr, HwSize size) {
    switch (size) {
        case HwSize::Byte:  return true;
        case HwSize::Word:  return (addr & 0x1) == 0;
        case HwSize::Dword: return (addr & 0x3) == 0;
        case HwSize::Qword: return (addr & 0x7) == 0;
    }
    return false;
}

std::uint64_t encodeRW(HwCondition c) {
    switch (c) {
        case HwCondition::Execute:   return 0b00;
        case HwCondition::Write:     return 0b01;
        case HwCondition::ReadWrite: return 0b11;
    }
    return 0;
}

std::uint64_t encodeLen(HwSize s, HwCondition c) {
    // Execute breakpoints must be LEN=00 regardless of nominal size.
    if (c == HwCondition::Execute) return 0b00;
    switch (s) {
        case HwSize::Byte:  return 0b00;
        case HwSize::Word:  return 0b01;
        case HwSize::Dword: return 0b11;
        case HwSize::Qword: return 0b10;
    }
    return 0;
}

} // anonymous

HwBpId HwBreakpointManager::add(Address addr, HwCondition cond, HwSize size) {
    if (cond != HwCondition::Execute && !aligned(addr, size)) return 0;

    // Reject exact-duplicate requests.
    for (const auto& s : m_slots) {
        if (s.active && s.addr == addr && s.cond == cond && s.size == size) {
            return 0;
        }
    }

    for (int i = 0; i < 4; ++i) {
        if (m_slots[i].active) continue;
        HwBreakpoint bp{};
        bp.id     = m_nextId++;
        bp.slot   = i;
        bp.addr   = addr;
        bp.cond   = cond;
        bp.size   = size;
        bp.active = true;
        m_slots[i] = bp;
        return bp.id;
    }
    return 0; // all 4 slots occupied
}

bool HwBreakpointManager::remove(HwBpId id) {
    for (auto& s : m_slots) {
        if (s.active && s.id == id) {
            s = HwBreakpoint{};  // clears active
            return true;
        }
    }
    return false;
}

std::vector<HwBreakpoint> HwBreakpointManager::list() const {
    std::vector<HwBreakpoint> out;
    for (const auto& s : m_slots) if (s.active) out.push_back(s);
    return out;
}

const HwBreakpoint* HwBreakpointManager::slot(int i) const {
    if (i < 0 || i >= 4) return nullptr;
    return &m_slots[i];
}

int HwBreakpointManager::firedSlot(std::uint64_t dr6) {
    if (dr6 & 0x1) return 0;
    if (dr6 & 0x2) return 1;
    if (dr6 & 0x4) return 2;
    if (dr6 & 0x8) return 3;
    return -1;
}

bool HwBreakpointManager::isExecuteSlot(int slot) const {
    if (slot < 0 || slot >= 4) return false;
    return m_slots[slot].active && m_slots[slot].cond == HwCondition::Execute;
}

// Build DR7 from the current slot state.
//   bits 0,2,4,6  : L0..L3 — local (per-thread) enable, 1 to arm
//   bits 8,9      : LE, GE — exact-match hints, recommended on
//   bits 16-17    : DR0 R/W   bits 18-19 : DR0 LEN
//   bits 20-21    : DR1 R/W   bits 22-23 : DR1 LEN
//   bits 24-25    : DR2 R/W   bits 26-27 : DR2 LEN
//   bits 28-29    : DR3 R/W   bits 30-31 : DR3 LEN
std::uint64_t HwBreakpointManager::computeDr7() const {
    std::uint64_t dr7 = (1ULL << 8) | (1ULL << 9);
    for (int i = 0; i < 4; ++i) {
        const auto& s = m_slots[i];
        if (!s.active) continue;
        dr7 |= (1ULL << (i * 2));                                    // L{i}
        dr7 |= encodeRW(s.cond) << (16 + i * 4);
        dr7 |= encodeLen(s.size, s.cond) << (18 + i * 4);
    }
    return dr7;
}

bool HwBreakpointManager::applyToThread(HANDLE thread) const {
    if (!thread) return false;
    CONTEXT c{};
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!::GetThreadContext(thread, &c)) return false;
    c.Dr0 = static_cast<DWORD64>(m_slots[0].active ? m_slots[0].addr : 0);
    c.Dr1 = static_cast<DWORD64>(m_slots[1].active ? m_slots[1].addr : 0);
    c.Dr2 = static_cast<DWORD64>(m_slots[2].active ? m_slots[2].addr : 0);
    c.Dr3 = static_cast<DWORD64>(m_slots[3].active ? m_slots[3].addr : 0);
    c.Dr7 = static_cast<DWORD64>(computeDr7());
    return ::SetThreadContext(thread, &c) != 0;
}

void HwBreakpointManager::applyToAll(const std::map<DWORD, HANDLE>& threads) const {
    for (const auto& kv : threads) applyToThread(kv.second);
}

} // namespace mdbg
