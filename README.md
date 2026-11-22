<div align="center">

# MiniDbg

**A small, readable x64 user-mode debugger for Windows.**

[![build](https://github.com/tertit133/minidbg/actions/workflows/build.yml/badge.svg)](https://github.com/tertit133/minidbg/actions/workflows/build.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C%2B%2B-20-00599C.svg?logo=c%2B%2B)](https://en.cppreference.com/w/cpp/20)
[![platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6.svg?logo=windows)](https://learn.microsoft.com/en-us/windows/win32/debug/)

ImGui + DX11 UI · Zydis disassembler · DbgHelp with symsrv · Lua 5.4 scripting

</div>

> Not a drop-in replacement for x64dbg — a compact codebase (~3.6k LOC)
> that shows how a real debugger is wired, end to end: the Win32 debug
> loop, software + hardware breakpoints, x64 unwinding, PE parsing,
> symbol resolution and an embedded scripting engine.

## Features

Shipped:

- [x] Launch a target `.exe` under the debugger (or attach to a running PID)
- [x] Event-driven debug loop (process / thread / DLL / BP / single-step)
- [x] Software breakpoints (INT3) with original-byte save, auto re-arm
- [x] Hardware breakpoints (DR0..DR3) — execute / write / read-write, 1/2/4/8 bytes
- [x] Conditional BPs — attach a Lua expression per BP, falsy = silent skip
- [x] Proper step-over (temp BP past `CALL`)
- [x] Live disassembly window at RIP (Zydis, Intel syntax)
- [x] Jump-to-address: pin disasm to any address or double-click a stack frame / export
- [x] General-purpose registers, flags, instruction pointer
- [x] Call stack via `StackWalk64` with DbgHelp symbols (module!symbol+offset)
- [x] PDB symbol server — pulls Microsoft public symbols for `kernel32!…` etc.
- [x] Memory hex view at user-entered address
- [x] Module list with imports/exports browser (live PE parsing via RPM)
- [x] Lua scripting (sol2 + Lua 5.4) — memory read/write, register access, BP control
- [x] ImGui docking — drag, split, float any pane; layout persists in `imgui.ini`
- [x] Log pane (process/thread/DLL events, OutputDebugString forwarded)

## Build

Prerequisites:

- Windows 10/11 x64
- Visual Studio 2022 (MSVC, x64 Native Tools) **or** CMake + Ninja with MSVC
- CMake 3.20+
- Git (CMake FetchContent pulls Zydis and Dear ImGui automatically)

```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
build\bin\Release\minidbg.exe
```

Or Ninja:

```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
build\bin\minidbg.exe
```

First configure pulls ~50 MB of deps and takes a minute.

## Architecture

```
src/
├── common.h         types, enums, UTF-8/wide, Windows includes
├── process.{h,cpp}  process enumeration, launch (debug flag), attach
├── disasm.{h,cpp}   Zydis wrapper, DecodedInsn, branch classification
├── context.{h,cpp}  thread context capture/apply, TF helper
├── breakpoint.{h,cpp}    soft BP manager (INT3 + optional Lua condition)
├── hwbreakpoint.{h,cpp}  hardware BP manager (4 slots, DR0..DR3 + DR7)
├── pe.{h,cpp}            live PE header reader — imports, exports, SizeOfImage
├── symbols.{h,cpp}       DbgHelp wrapper: symsrv, module loading, StackWalk64
├── scripting.{h,cpp}     sol2/Lua bindings (PImpl'd so sol2 headers stay out of core)
├── debugger.{h,cpp}    worker thread, event loop, state machine
├── ui/
│   ├── theme.{h,cpp}   gray ImGui style
│   ├── app.{h,cpp}     Win32 window + DX11 + ImGui bootstrap
│   └── views.{h,cpp}   disasm/regs/memory/bps/log/control bar
└── main.cpp         WinMain
```

The `Debugger` runs its own worker thread so that `WaitForDebugEventEx`
can block without freezing the UI. The UI pulls state via a mutex-guarded
`snapshot()` each frame and pushes user commands into a condition-variable
queue. All actual memory / context work happens on the worker thread.

## Software breakpoint flow

```
BP hit (0xCC exception)
  ↓
restore original byte at RIP-1
  ↓
rewind RIP by 1 (so the original insn executes)
  ↓
pause, notify UI, wait for command
  ↓
Run / StepInto → set TF (single-step), continue
  ↓
single-step exception fires after that one insn
  ↓
re-arm BP (write 0xCC back), clear TF
  ↓
continue (or pause again if StepInto)
```

## Hardware breakpoints

Hardware BPs live in the CPU, not the code — the debuggee's bytes are not
modified, so anti-cheat scanners that hunt for `0xCC` see nothing. Four
slots total (DR0..DR3), per-thread, configurable for:

- `exec`  — fire *before* the instruction at `addr` runs (LEN forced to 1)
- `write` — fire *after* a write touches `[addr .. addr+size)`
- `r/w`   — fire *after* any access to `[addr .. addr+size)` (useful for
  "who reads this variable?")

Data breakpoints must be naturally aligned (2-byte on even, 4-byte on
multiples of 4, etc.). `DR7` is rebuilt from the slot table and pushed to
every thread of the debuggee on each pause; `CREATE_THREAD_DEBUG_EVENT`
also applies the current state so new threads inherit the HBPs.

On hit, Windows raises `EXCEPTION_SINGLE_STEP` — DR6 bits B0-B3 identify
the slot. The engine clears DR6 and, for execute HBPs, sets the RF flag
in EFLAGS before continuing so the resumed instruction is not re-trapped
immediately (RF auto-clears after one instruction).

## Call stack

The x64 calling convention omits frame pointers by default. Instead,
each module ships unwind tables (`.pdata` / `.xdata`) that describe how
each prologue sets up the frame, and `StackWalk64` uses those tables via
the `SymFunctionTableAccess64` / `SymGetModuleBase64` callbacks to walk
back through the return addresses.

MiniDbg feeds DbgHelp every module it sees: `CREATE_PROCESS_DEBUG_EVENT`
loads the main image, `LOAD_DLL_DEBUG_EVENT` loads each DLL,
`UNLOAD_DLL_DEBUG_EVENT` drops it. When the debuggee pauses, the UI
pulls the current thread's stack via `Debugger::callStack()`; each
frame's RIP is then resolved to `module!symbol+offset` with
`SymGetModuleInfoW64` + `SymFromAddr`. If PDBs are present, you get
proper names; otherwise you still see module-base offsets, which are
plenty to navigate reverse-engineered binaries.

The stack pane only re-walks when RIP changes — UI stays cheap.

## Modules + PE parsing

The Modules tab lists every loaded image the engine has seen via
`CREATE_PROCESS_DEBUG_EVENT` and `LOAD_DLL_DEBUG_EVENT`. Picking a module
triggers two live reads from the debuggee memory:

- **Exports**: `IMAGE_EXPORT_DIRECTORY` → `AddressOfFunctions` + name /
  ordinal tables, with forwarded entries flagged separately.
- **Imports**: `IMAGE_IMPORT_DESCRIPTOR` chain → per-DLL function lists,
  including ordinal-only imports (`#123`).

Double-click an export row to focus the disassembly pane on it.
Everything comes from `ReadProcessMemory` against the running image, so
you see the actual state after loader fixups — no file-vs-memory drift.

## Lua scripting

The Lua tab embeds Lua 5.4 through sol2. Quick reference:

```lua
-- memory
local hp = dbg.readU32(0x7FF7B2340800)
dbg.writeU32(0x7FF7B2340800, 999)

-- registers
print(string.format("rip = 0x%X, rax = 0x%X", dbg.rip(), dbg.rax()))

-- control flow
local id = dbg.addBp(0x7FF7B23420A0)
dbg.continueExec()
-- after a hit:
dbg.stepOver()
dbg.rmBp(id)
```

Bindings cover `readU8/16/32/64`, `writeU8/16/32/64`, `readPtr`,
`readBytes(addr, n)`, every GPR, `addBp`/`rmBp`, and the three run
controls. `print()` and `dbg.log(s)` route into the pane's output box,
not stdout, so you see them even though MiniDbg is a GUI app.

sol2 is header-only. Lua 5.4 is vendored as a static library — CMake
fetches the official source tarball from the upstream GitHub mirror and
compiles it in-tree, no system Lua required.

### Conditional breakpoints

Each software breakpoint carries an optional Lua condition. On hit, the
engine evaluates the expression; a falsy result silently re-arms the BP
and keeps the debuggee running — the UI never flashes a pause. Perfect
for "stop me only when `rax == 42`" or filtering hot functions.

```
# Breakpoints pane → select a BP → paste in the editor:
return dbg.rax() == 0x42 and dbg.readU32(0x7FF7B2340800) > 100
```

The condition is wrapped in `return (…)` first so bare expressions work;
multi-line blocks that do their own `return` are supported too. Errors
pause instead of silently skipping so broken conditions can't eat hits.

## Symbol server

On first attach the engine installs a DbgHelp search path pointing at
Microsoft's public symbol store, cached under
`%LOCALAPPDATA%\minidbg-symbols`. That means the first time you touch
`kernel32!CreateFileW` the debugger quietly downloads kernel32's PDB and
every later resolution hits the local cache. The Modules pane has a
field to override this at runtime (or set `_NT_SYMBOL_PATH` in your
environment before launch to pin it).

## Layout / docking

MiniDbg uses the ImGui docking branch. Every pane is a top-level window:
drag the tab bar to move it, drop onto another pane to tab-group, drop
outside the main window to float it. The layout persists in `imgui.ini`
next to the executable, so your setup survives restarts. Delete the file
to rebuild the default split (control bar on top, disassembly + regs +
stack on the left, everything else tabbed on the right).

## License

MIT. See `LICENSE`.
