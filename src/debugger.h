// debugger.h — Win32 debugger engine. Owns the worker thread, event loop,
// state machine, and all cross-thread synchronisation with the UI.
#pragma once

#include "breakpoint.h"
#include "common.h"
#include "context.h"
#include "disasm.h"
#include "hwbreakpoint.h"
#include "pe.h"
#include "procmgr.h"
#include "scripting.h"
#include "symbols.h"

namespace mdbg {

enum class RunCommand {
    None,
    Continue,     // let the debuggee run
    StepInto,     // single instruction, then pause
    StepOver,     // step but treat a CALL as one unit
    Detach,
};

// A point-in-time view of the engine for the UI. Copied under lock so the
// UI thread can read without blocking the worker for more than a moment.
struct DebuggerSnapshot {
    DebuggerState state{DebuggerState::Idle};
    DWORD         pid{};
    DWORD         currentTid{};
    Address       rip{};
    CONTEXT       ctx{};
    Bytes         ripWindow;      // bytes beginning at ripWindowBase
    Address       ripWindowBase{};
};

class Debugger {
public:
    Debugger();
    ~Debugger();

    Debugger(const Debugger&) = delete;
    Debugger& operator=(const Debugger&) = delete;

    // Lifecycle --------------------------------------------------------------
    bool launch(const std::wstring& exePath, const std::wstring& args = {});
    bool attach(DWORD pid);
    void stop();                       // detach + join worker

    // Run / step controls — all non-blocking, they enqueue to the worker.
    void run();
    void breakIn();                    // DebugBreakProcess (async)
    void stepInto();
    void stepOver();

    // Breakpoints -----------------------------------------------------------
    BreakpointId addBreakpoint(Address addr);
    bool         removeBreakpoint(BreakpointId id);
    bool         setBreakpointScript(BreakpointId id, const std::string& script);
    std::vector<Breakpoint> breakpoints();

    // Hardware breakpoints (4 slots total).
    HwBpId addHwBreakpoint(Address addr, HwCondition cond, HwSize size);
    bool   removeHwBreakpoint(HwBpId id);
    std::vector<HwBreakpoint> hwBreakpoints();

    // Call stack for the currently-selected thread. Valid only while
    // paused; returns empty otherwise.
    std::vector<StackFrame> callStack();

    // Loaded modules (tracked from LOAD_DLL/UNLOAD_DLL events).
    struct Module {
        Address      base{};
        DWORD        size{};
        std::wstring name;    // basename without extension
        std::wstring path;    // full path
    };
    std::vector<Module> modules();
    std::vector<PeImport> moduleImports(Address base);
    std::vector<PeExport> moduleExports(Address base);

    // Lua scripting engine (bound at construction, UI thread only).
    Scripting& scripting() { return m_scripting; }

    // Symbol search path (symsrv syntax). See Symbols::defaultSearchPath().
    bool         setSymSearchPath(const std::wstring& path);
    std::wstring symSearchPath();

    // Memory -----------------------------------------------------------------
    bool readMemory(Address addr, void* buf, std::size_t size);
    bool writeMemory(Address addr, const void* buf, std::size_t size);

    // UI pulls these each frame.
    DebuggerSnapshot            snapshot();
    std::vector<std::string>    drainLog();
    std::vector<DebugEvent>     drainEvents();

    bool isAttached() const { return m_running.load(); }

private:
    void workerLoop();
    void handleEvent(const DEBUG_EVENT& ev, DWORD& continueStatus);
    void handleException(const DEBUG_EVENT& ev, DWORD& continueStatus);

    void dispatchCommand(DWORD tid, DWORD& continueStatus);

    void pushLog(std::string s);
    void pushEvent(DebugEvent e);

    void       postCommand(RunCommand c);
    RunCommand popCommand();    // blocks until something arrives

    HANDLE threadByTid(DWORD tid) const;

    // Startup state carried across the launch() → worker boundary.
    struct StartupPlan {
        enum class Mode { None, Launch, Attach } mode{Mode::None};
        std::wstring exe;
        std::wstring args;
        DWORD        pid{};
    };

private:
    void trackModule(Address base);
    void untrackModule(Address base);

    std::thread      m_worker;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_quit{false};

    // Command queue (UI → worker)
    std::mutex              m_cmdMtx;
    std::condition_variable m_cmdCv;
    std::queue<RunCommand>  m_cmdQ;

    // Engine state (worker owns writes, UI reads under lock)
    mutable std::mutex              m_stateMtx;
    std::atomic<DebuggerState>      m_state{DebuggerState::Idle};
    ProcessInfo                  m_proc{};
    std::map<DWORD, HANDLE>      m_threads;
    std::map<Address, Module>    m_modules;
    DWORD                        m_currentTid{};
    BreakpointManager            m_bps;
    HwBreakpointManager          m_hwBps;
    Disassembler                 m_dasm;
    Symbols                      m_symbols;
    Scripting                    m_scripting;

    // BP-recovery bookkeeping (worker only)
    Address m_pendingRearm{};
    Address m_stepOverReturnBp{};   // addr of temp BP set for step-over
    bool    m_pauseAfterStep{};     // true → pause when next SS fires
    DWORD   m_pendingRfTid{};       // set RF on this thread before continue

    // Log + events (UI drains)
    std::mutex                  m_logMtx;
    std::vector<std::string>    m_log;
    std::vector<DebugEvent>     m_events;

    StartupPlan m_plan;
};

} // namespace mdbg
