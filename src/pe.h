// pe.h — minimal PE header reader for the debuggee's loaded modules
//
// Everything is read live via ReadProcessMemory against the target
// process so these functions work equally well for the main image and
// for each loaded DLL. x64 only.
#pragma once

#include "common.h"

namespace mdbg {

struct PeExport {
    std::string name;
    Address     address{};  // absolute (module base + RVA)
    DWORD       ordinal{};
    bool        forwarded{}; // points into another DLL's export
};

struct PeImport {
    std::string dll;
    struct Entry {
        std::string name;    // "#123" if imported by ordinal
        DWORD       ordinal{};
        bool        byOrdinal{};
    };
    std::vector<Entry> entries;
};

// Image size from OptionalHeader. Returns 0 on failure.
DWORD readImageSize(HANDLE process, Address base);

std::vector<PeExport> readExports(HANDLE process, Address base);
std::vector<PeImport> readImports(HANDLE process, Address base);

} // namespace mdbg
