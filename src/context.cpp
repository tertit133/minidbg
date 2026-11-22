#include "context.h"

namespace mdbg {

RegSnapshot captureContext(HANDLE thread) {
    RegSnapshot s{};
    s.ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS | CONTEXT_SEGMENTS;
    if (::GetThreadContext(thread, &s.ctx)) s.valid = true;
    return s;
}

bool applyContext(HANDLE thread, const CONTEXT& c) {
    return ::SetThreadContext(thread, &c) != 0;
}

void setSingleStep(CONTEXT& c, bool on) {
    constexpr DWORD64 TF = 0x100;
    if (on) c.EFlags |=  TF;
    else    c.EFlags &= ~TF;
}

} // namespace mdbg
