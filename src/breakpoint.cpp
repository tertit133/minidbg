#include "breakpoint.h"

namespace mdbg {

namespace {

bool readByte(HANDLE p, Address addr, Byte& out) {
    SIZE_T r = 0;
    return ::ReadProcessMemory(p, reinterpret_cast<LPCVOID>(addr),
                                &out, 1, &r) && r == 1;
}

bool writeByte(HANDLE p, Address addr, Byte b) {
    DWORD oldProt = 0;
    if (!::VirtualProtectEx(p, reinterpret_cast<LPVOID>(addr), 1,
                              PAGE_EXECUTE_READWRITE, &oldProt)) {
        return false;
    }
    SIZE_T w  = 0;
    BOOL   ok = ::WriteProcessMemory(p, reinterpret_cast<LPVOID>(addr),
                                      &b, 1, &w);
    DWORD tmp = 0;
    ::VirtualProtectEx(p, reinterpret_cast<LPVOID>(addr), 1, oldProt, &tmp);
    ::FlushInstructionCache(p, reinterpret_cast<LPCVOID>(addr), 1);
    return ok && w == 1;
}

} // anonymous

BreakpointId BreakpointManager::add(HANDLE process, Address addr) {
    for (auto& bp : m_bps) {
        if (bp.address == addr) return bp.id;
    }
    Byte orig = 0;
    if (!readByte(process, addr, orig)) return 0;
    if (!writeByte(process, addr, 0xCC)) return 0;

    Breakpoint bp{};
    bp.id           = m_next++;
    bp.address      = addr;
    bp.originalByte = orig;
    bp.enabled      = true;
    m_bps.push_back(bp);
    return bp.id;
}

bool BreakpointManager::remove(HANDLE process, BreakpointId id) {
    for (auto it = m_bps.begin(); it != m_bps.end(); ++it) {
        if (it->id == id) {
            if (it->enabled) writeByte(process, it->address, it->originalByte);
            m_bps.erase(it);
            return true;
        }
    }
    return false;
}

bool BreakpointManager::enable(HANDLE process, BreakpointId id, bool on) {
    for (auto& bp : m_bps) {
        if (bp.id != id) continue;
        if (bp.enabled == on) return true;
        bool ok = on ? writeByte(process, bp.address, 0xCC)
                     : writeByte(process, bp.address, bp.originalByte);
        if (ok) bp.enabled = on;
        return ok;
    }
    return false;
}

Breakpoint* BreakpointManager::find(Address addr) {
    for (auto& bp : m_bps) if (bp.address == addr) return &bp;
    return nullptr;
}

const Breakpoint* BreakpointManager::find(Address addr) const {
    for (const auto& bp : m_bps) if (bp.address == addr) return &bp;
    return nullptr;
}

bool BreakpointManager::restoreOriginal(HANDLE process, Address addr) {
    auto* bp = find(addr);
    if (!bp) return false;
    return writeByte(process, addr, bp->originalByte);
}

bool BreakpointManager::arm(HANDLE process, Address addr) {
    auto* bp = find(addr);
    if (!bp || !bp->enabled) return false;
    return writeByte(process, addr, 0xCC);
}

} // namespace mdbg
