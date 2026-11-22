#include "procmgr.h"

#include <tlhelp32.h>

namespace mdbg {

std::vector<ProcessList::Entry> ProcessList::enumerate() {
    std::vector<Entry> out;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe)) {
        do {
            out.push_back({ pe.th32ProcessID, pe.szExeFile });
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return out;
}

std::optional<ProcessInfo> launchDebuggee(const std::wstring& exePath,
                                           const std::wstring& args) {
    std::wstring cmd = L"\"" + exePath + L"\"";
    if (!args.empty()) {
        cmd += L" ";
        cmd += args;
    }

    // CreateProcess may modify the command-line buffer, so copy it.
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    const DWORD flags = DEBUG_ONLY_THIS_PROCESS;

    BOOL ok = ::CreateProcessW(
        exePath.c_str(),
        cmdline.data(),
        /*lpProcessAttributes*/ nullptr,
        /*lpThreadAttributes*/  nullptr,
        /*bInheritHandles*/     FALSE,
        flags,
        /*lpEnvironment*/       nullptr,
        /*lpCurrentDirectory*/  nullptr,
        &si, &pi);

    if (!ok) return std::nullopt;

    ProcessInfo info{};
    info.pid        = pi.dwProcessId;
    info.process    = pi.hProcess;
    info.mainThread = pi.hThread;
    info.imagePath  = exePath;
    return info;
}

bool attachDebuggee(DWORD pid) {
    return ::DebugActiveProcess(pid) != 0;
}

} // namespace mdbg
