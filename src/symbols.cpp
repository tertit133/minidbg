#include "symbols.h"

#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

namespace mdbg {

Symbols::~Symbols() { shutdown(); }

std::wstring Symbols::defaultSearchPath() {
    // Honour an explicit env setting if the user wants one.
    wchar_t env[2048]{};
    DWORD n = ::GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", env, 2048);
    if (n && n < 2048) return env;

    // Otherwise cache Microsoft public symbols under %LOCALAPPDATA%.
    wchar_t local[MAX_PATH]{};
    n = ::GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    std::wstring cache = n ? std::wstring(local) + L"\\minidbg-symbols"
                           : std::wstring(L"C:\\symbols");
    return L"srv*" + cache + L"*https://msdl.microsoft.com/download/symbols";
}

bool Symbols::initialize(HANDLE process) {
    if (m_initialized) return true;
    if (!process) return false;

    ::SymSetOptions(SYMOPT_UNDNAME |
                     SYMOPT_DEFERRED_LOADS |
                     SYMOPT_LOAD_LINES |
                     SYMOPT_AUTO_PUBLICS |
                     SYMOPT_FAIL_CRITICAL_ERRORS);

    const std::wstring path = defaultSearchPath();

    // invadeProc = FALSE: we'll feed modules manually via loadModule() so
    // the symbol cache stays in sync with LOAD_DLL / UNLOAD_DLL events.
    if (!::SymInitializeW(process, path.c_str(), FALSE)) return false;

    m_proc = process;
    m_initialized = true;
    return true;
}

bool Symbols::setSearchPath(const std::wstring& path) {
    if (!m_initialized) return false;
    return ::SymSetSearchPathW(m_proc, path.c_str()) != 0;
}

std::wstring Symbols::searchPath() const {
    if (!m_initialized) return {};
    wchar_t buf[2048]{};
    if (::SymGetSearchPathW(m_proc, buf, 2048)) return buf;
    return {};
}

void Symbols::shutdown() {
    if (!m_initialized) return;
    ::SymCleanup(m_proc);
    m_proc = nullptr;
    m_initialized = false;
}

void Symbols::loadModule(HANDLE file, Address base, DWORD size,
                          const std::wstring& path) {
    if (!m_initialized) return;
    ::SymLoadModuleExW(m_proc, file,
                        path.empty() ? nullptr : path.c_str(),
                        /*ModuleName*/ nullptr,
                        static_cast<DWORD64>(base),
                        size,
                        nullptr, 0);
}

void Symbols::unloadModule(Address base) {
    if (!m_initialized) return;
    ::SymUnloadModule64(m_proc, static_cast<DWORD64>(base));
}

ResolvedAddress Symbols::resolve(Address addr) {
    ResolvedAddress out{};
    out.address = addr;
    if (!m_initialized) return out;

    IMAGEHLP_MODULEW64 modInfo{};
    modInfo.SizeOfStruct = sizeof(modInfo);
    if (::SymGetModuleInfoW64(m_proc, static_cast<DWORD64>(addr), &modInfo)) {
        out.moduleBase = static_cast<Address>(modInfo.BaseOfImage);
        out.moduleName = modInfo.ModuleName;
        out.hasModule  = true;
    }

    constexpr std::size_t kMaxName = 512;
    alignas(SYMBOL_INFO) Byte buf[sizeof(SYMBOL_INFO) + kMaxName]{};
    auto* sym = reinterpret_cast<SYMBOL_INFO*>(buf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = kMaxName;

    DWORD64 disp = 0;
    if (::SymFromAddr(m_proc, static_cast<DWORD64>(addr), &disp, sym)) {
        out.symbolName   = sym->Name;
        out.displacement = disp;
        out.hasSymbol    = true;
    }
    return out;
}

std::vector<StackFrame> Symbols::walkStack(HANDLE thread, CONTEXT ctx,
                                            int maxFrames) {
    std::vector<StackFrame> out;
    if (!m_initialized || !thread) return out;

    STACKFRAME64 sf{};
    sf.AddrPC.Offset    = ctx.Rip;  sf.AddrPC.Mode    = AddrModeFlat;
    sf.AddrFrame.Offset = ctx.Rbp;  sf.AddrFrame.Mode = AddrModeFlat;
    sf.AddrStack.Offset = ctx.Rsp;  sf.AddrStack.Mode = AddrModeFlat;

    for (int i = 0; i < maxFrames; ++i) {
        if (!::StackWalk64(IMAGE_FILE_MACHINE_AMD64,
                            m_proc, thread,
                            &sf, &ctx,
                            /*ReadMemoryRoutine*/ nullptr,
                            ::SymFunctionTableAccess64,
                            ::SymGetModuleBase64,
                            /*TranslateAddress*/ nullptr)) {
            break;
        }
        if (!sf.AddrPC.Offset) break;

        StackFrame f{};
        f.index        = i;
        f.address      = static_cast<Address>(sf.AddrPC.Offset);
        f.frameBase    = static_cast<Address>(sf.AddrFrame.Offset);
        f.stackPointer = static_cast<Address>(sf.AddrStack.Offset);
        f.sym          = resolve(f.address);
        out.push_back(std::move(f));
    }
    return out;
}

} // namespace mdbg
