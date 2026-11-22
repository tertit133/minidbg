#include "debugger.h"

#include <psapi.h>

namespace mdbg {

Debugger::Debugger() {
    m_scripting.bind(this);
}

Debugger::~Debugger() {
    stop();
    if (m_proc.process)    ::CloseHandle(m_proc.process);
    if (m_proc.mainThread) ::CloseHandle(m_proc.mainThread);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
bool Debugger::launch(const std::wstring& exePath, const std::wstring& args) {
    if (m_running.load()) return false;
    m_plan = {StartupPlan::Mode::Launch, exePath, args, 0};
    m_running = true;
    m_quit    = false;
    m_worker  = std::thread(&Debugger::workerLoop, this);
    return true;
}

bool Debugger::attach(DWORD pid) {
    if (m_running.load()) return false;
    m_plan = {StartupPlan::Mode::Attach, {}, {}, pid};
    m_running = true;
    m_quit    = false;
    m_worker  = std::thread(&Debugger::workerLoop, this);
    return true;
}

void Debugger::stop() {
    if (!m_running.load() && !m_worker.joinable()) return;
    m_quit = true;
    postCommand(RunCommand::Detach);
    if (m_worker.joinable()) m_worker.join();
    m_running = false;
}

void Debugger::run()       { postCommand(RunCommand::Continue); }
void Debugger::stepInto()  { postCommand(RunCommand::StepInto); }
void Debugger::stepOver()  { postCommand(RunCommand::StepOver); }

void Debugger::breakIn() {
    HANDLE p{};
    {
        std::lock_guard<std::mutex> lk(m_stateMtx);
        p = m_proc.process;
    }
    if (p) ::DebugBreakProcess(p);
}

// ---------------------------------------------------------------------------
// Breakpoint API (UI thread)
// ---------------------------------------------------------------------------
BreakpointId Debugger::addBreakpoint(Address addr) {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    if (!m_proc.process) return 0;
    return m_bps.add(m_proc.process, addr);
}

bool Debugger::removeBreakpoint(BreakpointId id) {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    return m_bps.remove(m_proc.process, id);
}

std::vector<Breakpoint> Debugger::breakpoints() {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    return m_bps.list();
}

bool Debugger::setBreakpointScript(BreakpointId id, const std::string& script) {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    // BreakpointManager doesn't expose mutation, so reach in through find().
    // (Scripts live on the Breakpoint record, not in the on-target bytes.)
    auto& bps = const_cast<std::vector<Breakpoint>&>(m_bps.list());
    for (auto& bp : bps) {
        if (bp.id == id) { bp.script = script; return true; }
    }
    return false;
}

HwBpId Debugger::addHwBreakpoint(Address addr, HwCondition cond, HwSize size) {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    HwBpId id = m_hwBps.add(addr, cond, size);
    if (id) m_hwBps.applyToAll(m_threads);
    return id;
}

bool Debugger::removeHwBreakpoint(HwBpId id) {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    bool ok = m_hwBps.remove(id);
    if (ok) m_hwBps.applyToAll(m_threads);
    return ok;
}

std::vector<HwBreakpoint> Debugger::hwBreakpoints() {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    return m_hwBps.list();
}

std::vector<StackFrame> Debugger::callStack() {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    if (m_state != DebuggerState::Paused) return {};
    auto it = m_threads.find(m_currentTid);
    if (it == m_threads.end()) return {};
    auto snap = captureContext(it->second);
    if (!snap.valid) return {};
    return m_symbols.walkStack(it->second, snap.ctx);
}

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------
std::vector<Debugger::Module> Debugger::modules() {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    std::vector<Module> out;
    out.reserve(m_modules.size());
    for (const auto& kv : m_modules) out.push_back(kv.second);
    return out;
}

std::vector<PeImport> Debugger::moduleImports(Address base) {
    HANDLE p{};
    {
        std::lock_guard<std::mutex> lk(m_stateMtx);
        p = m_proc.process;
    }
    if (!p) return {};
    return readImports(p, base);
}

std::vector<PeExport> Debugger::moduleExports(Address base) {
    HANDLE p{};
    {
        std::lock_guard<std::mutex> lk(m_stateMtx);
        p = m_proc.process;
    }
    if (!p) return {};
    return readExports(p, base);
}

bool Debugger::setSymSearchPath(const std::wstring& path) {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    return m_symbols.setSearchPath(path);
}

std::wstring Debugger::symSearchPath() {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    return m_symbols.searchPath();
}

void Debugger::trackModule(Address base) {
    if (!base || !m_proc.process) return;

    Module m{};
    m.base = base;
    m.size = readImageSize(m_proc.process, base);

    wchar_t pathBuf[MAX_PATH]{};
    DWORD n = ::GetModuleFileNameExW(m_proc.process,
                                       reinterpret_cast<HMODULE>(base),
                                       pathBuf, MAX_PATH);
    if (n) {
        m.path = pathBuf;
        auto slash = m.path.find_last_of(L"\\/");
        std::wstring base_name = (slash == std::wstring::npos)
                                   ? m.path
                                   : m.path.substr(slash + 1);
        auto dot = base_name.find_last_of(L'.');
        m.name = (dot == std::wstring::npos) ? base_name
                                             : base_name.substr(0, dot);
    }

    std::lock_guard<std::mutex> lk(m_stateMtx);
    m_modules[base] = std::move(m);
}

void Debugger::untrackModule(Address base) {
    std::lock_guard<std::mutex> lk(m_stateMtx);
    m_modules.erase(base);
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------
bool Debugger::readMemory(Address addr, void* buf, std::size_t size) {
    HANDLE p;
    {
        std::lock_guard<std::mutex> lk(m_stateMtx);
        p = m_proc.process;
    }
    if (!p) return false;
    SIZE_T r = 0;
    return ::ReadProcessMemory(p, reinterpret_cast<LPCVOID>(addr),
                                buf, size, &r) && r == size;
}

bool Debugger::writeMemory(Address addr, const void* buf, std::size_t size) {
    HANDLE p;
    {
        std::lock_guard<std::mutex> lk(m_stateMtx);
        p = m_proc.process;
    }
    if (!p) return false;
    DWORD oldProt = 0;
    ::VirtualProtectEx(p, reinterpret_cast<LPVOID>(addr), size,
                        PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T w = 0;
    BOOL   ok = ::WriteProcessMemory(p, reinterpret_cast<LPVOID>(addr),
                                      buf, size, &w);
    DWORD tmp = 0;
    ::VirtualProtectEx(p, reinterpret_cast<LPVOID>(addr), size, oldProt, &tmp);
    ::FlushInstructionCache(p, reinterpret_cast<LPCVOID>(addr), size);
    return ok && w == size;
}

// ---------------------------------------------------------------------------
// UI pulls
// ---------------------------------------------------------------------------
DebuggerSnapshot Debugger::snapshot() {
    DebuggerSnapshot s{};
    HANDLE th = nullptr;
    HANDLE pr = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_stateMtx);
        s.state      = m_state;
        s.pid        = m_proc.pid;
        s.currentTid = m_currentTid;
        pr           = m_proc.process;
        auto it = m_threads.find(m_currentTid);
        if (it != m_threads.end()) th = it->second;
    }
    if (th) {
        auto snap = captureContext(th);
        if (snap.valid) {
            s.ctx = snap.ctx;
            s.rip = snap.ctx.Rip;
        }
    }
    if (pr && s.rip) {
        constexpr std::size_t kWindow = 128;
        s.ripWindowBase = s.rip;
        s.ripWindow.resize(kWindow);
        SIZE_T r = 0;
        ::ReadProcessMemory(pr, reinterpret_cast<LPCVOID>(s.rip),
                             s.ripWindow.data(), kWindow, &r);
        s.ripWindow.resize(r);
    }
    return s;
}

std::vector<std::string> Debugger::drainLog() {
    std::lock_guard<std::mutex> lk(m_logMtx);
    auto v = std::move(m_log);
    m_log.clear();
    return v;
}

std::vector<DebugEvent> Debugger::drainEvents() {
    std::lock_guard<std::mutex> lk(m_logMtx);
    auto v = std::move(m_events);
    m_events.clear();
    return v;
}

// ---------------------------------------------------------------------------
// Command queue
// ---------------------------------------------------------------------------
void Debugger::postCommand(RunCommand c) {
    {
        std::lock_guard<std::mutex> lk(m_cmdMtx);
        m_cmdQ.push(c);
    }
    m_cmdCv.notify_one();
}

RunCommand Debugger::popCommand() {
    std::unique_lock<std::mutex> lk(m_cmdMtx);
    m_cmdCv.wait(lk, [this]{ return !m_cmdQ.empty() || m_quit.load(); });
    if (m_quit.load()) return RunCommand::Detach;
    auto c = m_cmdQ.front();
    m_cmdQ.pop();
    return c;
}

HANDLE Debugger::threadByTid(DWORD tid) const {
    auto it = m_threads.find(tid);
    return it == m_threads.end() ? nullptr : it->second;
}

void Debugger::pushLog(std::string s) {
    std::lock_guard<std::mutex> lk(m_logMtx);
    m_log.push_back(std::move(s));
}

void Debugger::pushEvent(DebugEvent e) {
    std::lock_guard<std::mutex> lk(m_logMtx);
    m_events.push_back(std::move(e));
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------
void Debugger::workerLoop() {
    // Startup: launch or attach, record initial process info.
    if (m_plan.mode == StartupPlan::Mode::Launch) {
        auto info = launchDebuggee(m_plan.exe, m_plan.args);
        if (!info) {
            pushLog("[!] CreateProcess failed");
            m_running = false;
            std::lock_guard<std::mutex> lk(m_stateMtx);
            m_state = DebuggerState::Exited;
            return;
        }
        std::lock_guard<std::mutex> lk(m_stateMtx);
        m_proc  = *info;
        m_state = DebuggerState::Running;
    } else if (m_plan.mode == StartupPlan::Mode::Attach) {
        if (!::DebugActiveProcess(m_plan.pid)) {
            pushLog("[!] DebugActiveProcess failed");
            m_running = false;
            std::lock_guard<std::mutex> lk(m_stateMtx);
            m_state = DebuggerState::Exited;
            return;
        }
        std::lock_guard<std::mutex> lk(m_stateMtx);
        m_proc.pid = m_plan.pid;
        m_proc.process = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_plan.pid);
        m_state = DebuggerState::Running;
    }

    // DbgHelp lifecycle is tied to this process handle. Set it up before
    // the first LOAD_DLL event arrives so modules land into the symbol
    // cache as they come.
    if (m_proc.process) {
        if (!m_symbols.initialize(m_proc.process)) {
            pushLog("[!] SymInitialize failed — symbols disabled");
        }
    }

    pushLog(sfmt("[*] worker started, pid=%lu", m_proc.pid));

    DEBUG_EVENT ev{};
    while (m_running.load() && !m_quit.load()) {
        if (!::WaitForDebugEventEx(&ev, 100)) {
            // 100 ms tick — lets quit flag check the loop.
            DWORD err = ::GetLastError();
            if (err == ERROR_SEM_TIMEOUT) continue;
            pushLog(sfmt("[!] WaitForDebugEventEx failed: %lu", err));
            break;
        }

        DWORD continueStatus = DBG_CONTINUE;
        {
            std::lock_guard<std::mutex> lk(m_stateMtx);
            m_currentTid = ev.dwThreadId;
            m_state      = DebuggerState::Paused;
        }

        handleEvent(ev, continueStatus);

        // If the event left us paused (BP / step / unhandled exception),
        // wait for a user command to decide what to do next.
        bool paused = (m_state == DebuggerState::Paused && m_running.load());
        if (paused) {
            dispatchCommand(ev.dwThreadId, continueStatus);
        }

        // All threads are still suspended by the OS at this point — this is
        // the safe window to push HBP state onto every one (including any
        // thread that was just created by this event).
        {
            std::lock_guard<std::mutex> lk(m_stateMtx);
            m_hwBps.applyToAll(m_threads);
        }

        // If a HW execute-BP fired, we need the Resume Flag set so the first
        // instruction after continue doesn't immediately re-trigger it. RF
        // auto-clears after one instruction retires.
        if (m_pendingRfTid) {
            HANDLE h = threadByTid(m_pendingRfTid);
            if (h) {
                auto s = captureContext(h);
                if (s.valid) {
                    s.ctx.EFlags |= 0x10000;  // RF
                    applyContext(h, s.ctx);
                }
            }
            m_pendingRfTid = 0;
        }

        if (m_running.load()) {
            std::lock_guard<std::mutex> lk(m_stateMtx);
            m_state = DebuggerState::Running;
        }

        ::ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);
    }

    // Shutdown
    m_symbols.shutdown();
    if (m_proc.pid) ::DebugActiveProcessStop(m_proc.pid);
    {
        std::lock_guard<std::mutex> lk(m_stateMtx);
        m_state = DebuggerState::Exited;
    }
    pushLog("[*] worker exited");
}

void Debugger::dispatchCommand(DWORD tid, DWORD& continueStatus) {
    // continueStatus comes in set by the event handler — DBG_CONTINUE for
    // BP/SS/non-exception events, DBG_EXCEPTION_NOT_HANDLED for exceptions
    // we didn't consume. We only override when the user action demands it.
    RunCommand cmd = popCommand();

    auto setTF = [&](bool on) {
        HANDLE h = threadByTid(tid);
        if (!h) return;
        auto s = captureContext(h);
        if (!s.valid) return;
        setSingleStep(s.ctx, on);
        applyContext(h, s.ctx);
    };

    switch (cmd) {
        case RunCommand::Continue:
            m_pauseAfterStep = false;
            // If we have a BP to re-arm, we must single-step past the
            // original instruction first.
            if (m_pendingRearm) setTF(true);
            break;

        case RunCommand::StepInto:
            m_pauseAfterStep = true;
            setTF(true);
            break;

        case RunCommand::StepOver: {
            // If the next insn is a CALL, drop a one-shot BP past it.
            // Otherwise fall through to StepInto behaviour.
            m_pauseAfterStep = true;
            HANDLE h = threadByTid(tid);
            if (!h) break;
            auto s = captureContext(h);
            if (!s.valid) break;

            Byte insnBuf[16]{};
            SIZE_T r = 0;
            ::ReadProcessMemory(m_proc.process,
                                 reinterpret_cast<LPCVOID>(s.ctx.Rip),
                                 insnBuf, sizeof(insnBuf), &r);
            auto decoded = m_dasm.decode(s.ctx.Rip, insnBuf, r, 1);

            if (!decoded.empty() && decoded[0].isCall && decoded[0].length > 0) {
                Address retAddr = s.ctx.Rip + decoded[0].length;
                m_stepOverReturnBp = retAddr;
                m_bps.add(m_proc.process, retAddr);
                m_pauseAfterStep = false;   // pause via the temp BP, not SS
            } else {
                setSingleStep(s.ctx, true);
                applyContext(h, s.ctx);
            }
            break;
        }

        case RunCommand::Detach:
            m_running = false;
            continueStatus = DBG_CONTINUE;
            break;

        case RunCommand::None:
        default:
            break;
    }
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------
void Debugger::handleEvent(const DEBUG_EVENT& ev, DWORD& continueStatus) {
    switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            const auto& cp = ev.u.CreateProcessInfo;
            {
                std::lock_guard<std::mutex> lk(m_stateMtx);
                if (!m_proc.process) m_proc.process = cp.hProcess;
                m_threads[ev.dwThreadId] = cp.hThread;
                m_proc.imageBase = reinterpret_cast<Address>(cp.lpBaseOfImage);
            }
            // Re-init DbgHelp against the real hProcess when needed.
            if (!m_symbols.initialized()) m_symbols.initialize(m_proc.process);
            m_symbols.loadModule(cp.hFile, m_proc.imageBase, 0);
            trackModule(m_proc.imageBase);
            pushLog(sfmt("[+] process created pid=%lu base=0x%llX",
                          ev.dwProcessId,
                          static_cast<unsigned long long>(m_proc.imageBase)));
            pushEvent({DebugEvent::Kind::ProcessCreated,
                        ev.dwProcessId, ev.dwThreadId, m_proc.imageBase, 0, {}});
            if (cp.hFile) ::CloseHandle(cp.hFile);
            // Process is suspended at loader BP; stay paused for user input.
            m_state = DebuggerState::Paused;
            break;
        }

        case CREATE_THREAD_DEBUG_EVENT: {
            {
                std::lock_guard<std::mutex> lk(m_stateMtx);
                m_threads[ev.dwThreadId] = ev.u.CreateThread.hThread;
            }
            pushLog(sfmt("[+] thread %lu created", ev.dwThreadId));
            continueStatus = DBG_CONTINUE;
            break;
        }

        case EXIT_THREAD_DEBUG_EVENT: {
            {
                std::lock_guard<std::mutex> lk(m_stateMtx);
                m_threads.erase(ev.dwThreadId);
            }
            pushLog(sfmt("[-] thread %lu exited code=%lu",
                          ev.dwThreadId, ev.u.ExitThread.dwExitCode));
            continueStatus = DBG_CONTINUE;
            break;
        }

        case LOAD_DLL_DEBUG_EVENT: {
            const auto& ld = ev.u.LoadDll;
            Address base = reinterpret_cast<Address>(ld.lpBaseOfDll);
            m_symbols.loadModule(ld.hFile, base, 0);
            trackModule(base);
            pushLog(sfmt("[+] dll loaded at 0x%llX",
                          static_cast<unsigned long long>(base)));
            if (ld.hFile) ::CloseHandle(ld.hFile);
            continueStatus = DBG_CONTINUE;
            break;
        }

        case UNLOAD_DLL_DEBUG_EVENT: {
            Address base = reinterpret_cast<Address>(ev.u.UnloadDll.lpBaseOfDll);
            m_symbols.unloadModule(base);
            untrackModule(base);
            pushLog(sfmt("[-] dll unloaded at 0x%llX",
                          static_cast<unsigned long long>(base)));
            continueStatus = DBG_CONTINUE;
            break;
        }

        case OUTPUT_DEBUG_STRING_EVENT: {
            const auto& ds = ev.u.DebugString;
            std::vector<char> str(ds.nDebugStringLength + 1u, '\0');
            SIZE_T r = 0;
            if (m_proc.process) {
                ::ReadProcessMemory(m_proc.process, ds.lpDebugStringData,
                                     str.data(), ds.nDebugStringLength, &r);
            }
            str.back() = '\0';
            pushLog(sfmt("[dbgstr] %s", str.data()));
            continueStatus = DBG_CONTINUE;
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT: {
            pushLog(sfmt("[-] process exited code=%lu",
                          ev.u.ExitProcess.dwExitCode));
            pushEvent({DebugEvent::Kind::ProcessExited,
                        ev.dwProcessId, ev.dwThreadId, 0,
                        ev.u.ExitProcess.dwExitCode, {}});
            m_running = false;
            continueStatus = DBG_CONTINUE;
            break;
        }

        case EXCEPTION_DEBUG_EVENT:
            handleException(ev, continueStatus);
            break;

        default:
            continueStatus = DBG_CONTINUE;
            break;
    }
}

void Debugger::handleException(const DEBUG_EVENT& ev, DWORD& continueStatus) {
    const auto& er   = ev.u.Exception.ExceptionRecord;
    const DWORD code = er.ExceptionCode;
    const auto  addr = reinterpret_cast<Address>(er.ExceptionAddress);
    HANDLE      h    = threadByTid(ev.dwThreadId);

    switch (code) {
        case EXCEPTION_BREAKPOINT: {
            Breakpoint* bp = m_bps.find(addr);
            if (bp) {
                // Restore the original byte and rewind RIP by 1 so the
                // original instruction will execute on the next continue.
                m_bps.restoreOriginal(m_proc.process, addr);
                if (h) {
                    auto s = captureContext(h);
                    if (s.valid) {
                        s.ctx.Rip = addr;
                        applyContext(h, s.ctx);
                    }
                }
                m_pendingRearm = addr;

                const bool isStepOverHit = (addr == m_stepOverReturnBp);
                if (isStepOverHit) {
                    m_bps.remove(m_proc.process, bp->id);
                    m_stepOverReturnBp = 0;
                    m_pendingRearm = 0;
                }

                // Conditional BP: evaluate the attached Lua expression.
                // A falsy result silently re-arms and continues — the
                // user never sees the hit. Errors are treated as "pause"
                // so broken conditions are obvious.
                bool silent = false;
                if (!isStepOverHit && bp && !bp->script.empty()) {
                    if (!m_scripting.evalCondition(bp->script)) silent = true;
                }

                if (silent) {
                    if (h) {
                        auto s = captureContext(h);
                        if (s.valid) {
                            setSingleStep(s.ctx, true);
                            applyContext(h, s.ctx);
                        }
                    }
                    m_pauseAfterStep = false;
                    m_state = DebuggerState::Running;
                    continueStatus = DBG_CONTINUE;
                    break;
                }

                pushLog(sfmt("[*] breakpoint hit at 0x%llX",
                              static_cast<unsigned long long>(addr)));
                pushEvent({DebugEvent::Kind::BreakpointHit,
                            ev.dwProcessId, ev.dwThreadId, addr, code, {}});
                m_state = DebuggerState::Paused;
                continueStatus = DBG_CONTINUE;
            } else {
                // First breakpoint = loader-initiated. Perfect pause point.
                pushLog(sfmt("[*] system breakpoint at 0x%llX",
                              static_cast<unsigned long long>(addr)));
                m_state = DebuggerState::Paused;
                continueStatus = DBG_CONTINUE;
            }
            break;
        }

        case EXCEPTION_SINGLE_STEP: {
            // Single-step events come from two sources on x64:
            //   1. our TF (Trap Flag) was set to run one insn after a soft BP
            //      or to service a StepInto;
            //   2. a hardware breakpoint fired (DR0..DR3). DR6 bits B0-B3
            //      tell us which slot, and BS tells us it was a TF step.
            int hwSlot = -1;
            if (h) {
                auto s = captureContext(h);
                if (s.valid) {
                    hwSlot = HwBreakpointManager::firedSlot(s.ctx.Dr6);
                    // Clear B0-B3 and BS so DR6 doesn't stay dirty.
                    s.ctx.Dr6 &= ~0xF;
                    s.ctx.Dr6 &= ~0x4000ULL;
                    applyContext(h, s.ctx);
                }
            }

            if (hwSlot >= 0) {
                const HwBreakpoint* b = m_hwBps.slot(hwSlot);
                pushLog(sfmt("[*] hw breakpoint hit at 0x%llX (DR%d)",
                              static_cast<unsigned long long>(addr), hwSlot));
                pushEvent({DebugEvent::Kind::BreakpointHit,
                            ev.dwProcessId, ev.dwThreadId,
                            b ? b->addr : addr, code, {}});
                // Execute-type HBPs fire before the instruction retires;
                // RF (set before continue) skips retrigger on resume.
                if (m_hwBps.isExecuteSlot(hwSlot)) m_pendingRfTid = ev.dwThreadId;
                m_state = DebuggerState::Paused;
                continueStatus = DBG_CONTINUE;
                break;
            }

            // Plain TF single-step: finish the soft-BP recovery dance or
            // service a user StepInto.
            if (m_pendingRearm) {
                m_bps.arm(m_proc.process, m_pendingRearm);
                m_pendingRearm = 0;
            }
            pushEvent({DebugEvent::Kind::SingleStep,
                        ev.dwProcessId, ev.dwThreadId, addr, code, {}});
            if (m_pauseAfterStep) {
                m_pauseAfterStep = false;
                m_state = DebuggerState::Paused;
                pushLog(sfmt("[*] single-step at 0x%llX",
                              static_cast<unsigned long long>(addr)));
            } else {
                if (h) {
                    auto s = captureContext(h);
                    if (s.valid) {
                        setSingleStep(s.ctx, false);
                        applyContext(h, s.ctx);
                    }
                }
                m_state = DebuggerState::Running;
            }
            continueStatus = DBG_CONTINUE;
            break;
        }

        default: {
            pushLog(sfmt("[!] exception 0x%08X at 0x%llX",
                          code, static_cast<unsigned long long>(addr)));
            pushEvent({DebugEvent::Kind::Exception,
                        ev.dwProcessId, ev.dwThreadId, addr, code, {}});
            m_state = DebuggerState::Paused;
            // Let the debuggee see it only after the user decides.
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }
    }
}

} // namespace mdbg
