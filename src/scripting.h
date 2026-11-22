// scripting.h — Lua (sol2) bindings for the debugger.
//
// Exposes a `dbg` namespace inside Lua with memory read/write, register
// access, log and control helpers. sol2 headers are heavy, so they live
// behind a PImpl — downstream code (UI, debugger.h) only sees the opaque
// class.
#pragma once

#include "common.h"

namespace mdbg {

class Debugger;

class Scripting {
public:
    Scripting();
    ~Scripting();

    Scripting(const Scripting&) = delete;
    Scripting& operator=(const Scripting&) = delete;

    void bind(Debugger* dbg);

    // Execute a chunk of Lua. Returns a short status string
    // ("ok", "error: ...") and pushes any print()/dbg.log() output into
    // the drain queue below.
    std::string eval(const std::string& code);

    // Evaluate `code` as a boolean condition. Tries `return (code)` first
    // so a bare expression works; falls back to running `code` as a block
    // and reading its top-of-stack value. Errors return true so the user
    // notices the mistake at the next hit rather than silently losing BPs.
    bool evalCondition(const std::string& code);

    // Buffered output from print() / dbg.log(); UI drains each frame.
    std::vector<std::string> drainOutput();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace mdbg
