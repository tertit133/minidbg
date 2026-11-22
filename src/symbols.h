// symbols.h — DbgHelp wrapper: module/symbol resolution + stack walking
//
// On x64 the stack cannot be unwound by just following RBP — the
// compiler usually omits the frame pointer and encodes unwind info in
// the module's .pdata/.xdata tables. StackWalk64 reads those tables via
// SymFunctionTableAccess64/SymGetModuleBase64 callbacks, so we need
// DbgHelp set up with the debuggee's loaded modules before we can walk.
#pragma once

#include "common.h"

namespace mdbg {

struct ResolvedAddress {
    Address      address{};
    Address      moduleBase{};
    std::wstring moduleName;   // without extension
    std::string  symbolName;   // undecorated if available
    DWORD64      displacement{};
    bool         hasSymbol{};
    bool         hasModule{};
};

struct StackFrame {
    int             index{};
    Address         address{};        // RIP within this frame
    Address         frameBase{};      // AddrFrame
    Address         stackPointer{};   // AddrStack
    ResolvedAddress sym;
};

class Symbols {
public:
    Symbols() = default;
    ~Symbols();

    Symbols(const Symbols&) = delete;
    Symbols& operator=(const Symbols&) = delete;

    bool initialize(HANDLE process);
    void shutdown();

    // DbgHelp symbol-search path. Supports symsrv syntax, e.g.
    //   srv*C:\symbols*https://msdl.microsoft.com/download/symbols
    // If _NT_SYMBOL_PATH is set in the environment at initialize() time
    // it's used verbatim; otherwise the engine installs a default that
    // caches Microsoft public symbols under %LOCALAPPDATA%.
    bool setSearchPath(const std::wstring& path);
    std::wstring searchPath() const;
    static std::wstring defaultSearchPath();

    // Register a module with DbgHelp. Pass the hFile from CREATE_PROCESS /
    // LOAD_DLL debug events when available (DbgHelp can derive the path
    // from the mapping). `size = 0` lets DbgHelp auto-detect from headers.
    void loadModule(HANDLE file, Address base, DWORD size,
                    const std::wstring& path = {});
    void unloadModule(Address base);

    ResolvedAddress resolve(Address addr);

    // StackWalk64 mutates the CONTEXT it gets, so we take it by value.
    std::vector<StackFrame> walkStack(HANDLE thread, CONTEXT ctx,
                                       int maxFrames = 64);

    bool initialized() const { return m_initialized; }

private:
    HANDLE m_proc{};
    bool   m_initialized{};
};

} // namespace mdbg
