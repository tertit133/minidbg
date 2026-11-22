// context.h — thread context (register state) helpers
#pragma once

#include "common.h"

namespace mdbg {

struct RegSnapshot {
    DWORD   tid{};
    CONTEXT ctx{};
    bool    valid{};
};

RegSnapshot captureContext(HANDLE thread);
bool        applyContext(HANDLE thread, const CONTEXT& c);

// Flip the TF (Trap Flag) bit in EFLAGS. One instruction executes after
// continue, then EXCEPTION_SINGLE_STEP fires.
void setSingleStep(CONTEXT& c, bool on);

} // namespace mdbg
