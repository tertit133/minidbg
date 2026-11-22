// process.h — process enumeration, launch (debug), attach
#pragma once

#include "common.h"

namespace mdbg {

struct ProcessInfo {
    DWORD        pid{};
    HANDLE       process{};       // may be filled in later by CREATE_PROCESS_DEBUG_EVENT
    HANDLE       mainThread{};
    Address      imageBase{};
    std::wstring imagePath;
};

class ProcessList {
public:
    struct Entry {
        DWORD        pid;
        std::wstring name;
    };
    static std::vector<Entry> enumerate();
};

// Launch a new process in debug-only mode. Returns ProcessInfo on success.
// Caller owns process/thread handles returned here and should NOT close them —
// the debug loop takes ownership on the first CREATE_PROCESS_DEBUG_EVENT.
std::optional<ProcessInfo> launchDebuggee(const std::wstring& exePath,
                                           const std::wstring& args = {});

// Attach the calling thread's debugger to an existing process.
bool attachDebuggee(DWORD pid);

} // namespace mdbg
