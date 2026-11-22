#include "pe.h"

#include <cstring>

namespace mdbg {

namespace {

template <typename T>
bool rpm(HANDLE p, Address addr, T& out) {
    SIZE_T r = 0;
    return ::ReadProcessMemory(p, reinterpret_cast<LPCVOID>(addr),
                                &out, sizeof(T), &r) && r == sizeof(T);
}

bool rpmBuf(HANDLE p, Address addr, void* out, std::size_t n) {
    SIZE_T r = 0;
    return ::ReadProcessMemory(p, reinterpret_cast<LPCVOID>(addr),
                                out, n, &r) && r == n;
}

// Read a null-terminated ASCII string from the debuggee.
std::string readCString(HANDLE p, Address addr, std::size_t max = 256) {
    std::string out(max, '\0');
    SIZE_T r = 0;
    if (!::ReadProcessMemory(p, reinterpret_cast<LPCVOID>(addr),
                               out.data(), max, &r)) {
        return {};
    }
    out.resize(r);
    auto zero = out.find('\0');
    if (zero != std::string::npos) out.resize(zero);
    return out;
}

struct PeHeaders {
    IMAGE_DOS_HEADER     dos{};
    IMAGE_NT_HEADERS64   nt{};
    bool                 ok{};
};

PeHeaders readPeHeaders(HANDLE process, Address base) {
    PeHeaders h{};
    if (!rpm(process, base, h.dos))       return h;
    if (h.dos.e_magic != IMAGE_DOS_SIGNATURE) return h;
    if (!rpm(process, base + h.dos.e_lfanew, h.nt)) return h;
    if (h.nt.Signature != IMAGE_NT_SIGNATURE) return h;
    if (h.nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return h;
    h.ok = true;
    return h;
}

} // anonymous

DWORD readImageSize(HANDLE process, Address base) {
    PeHeaders h = readPeHeaders(process, base);
    return h.ok ? h.nt.OptionalHeader.SizeOfImage : 0;
}

std::vector<PeExport> readExports(HANDLE process, Address base) {
    std::vector<PeExport> out;

    PeHeaders h = readPeHeaders(process, base);
    if (!h.ok) return out;

    const auto& dir = h.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return out;

    IMAGE_EXPORT_DIRECTORY ed{};
    if (!rpm(process, base + dir.VirtualAddress, ed)) return out;

    if (ed.NumberOfFunctions == 0) return out;

    std::vector<DWORD> funcRvas(ed.NumberOfFunctions);
    if (!rpmBuf(process, base + ed.AddressOfFunctions,
                 funcRvas.data(), funcRvas.size() * sizeof(DWORD))) {
        return out;
    }

    std::vector<DWORD> nameRvas(ed.NumberOfNames);
    std::vector<WORD>  ordinals(ed.NumberOfNames);
    if (ed.NumberOfNames) {
        if (!rpmBuf(process, base + ed.AddressOfNames,
                     nameRvas.data(), nameRvas.size() * sizeof(DWORD))) return out;
        if (!rpmBuf(process, base + ed.AddressOfNameOrdinals,
                     ordinals.data(), ordinals.size() * sizeof(WORD))) return out;
    }

    // Map ordinal → name for the named exports.
    std::vector<std::string> namesByOrd(ed.NumberOfFunctions);
    for (DWORD i = 0; i < ed.NumberOfNames; ++i) {
        WORD o = ordinals[i];
        if (o < ed.NumberOfFunctions) {
            namesByOrd[o] = readCString(process, base + nameRvas[i]);
        }
    }

    for (DWORD i = 0; i < ed.NumberOfFunctions; ++i) {
        if (!funcRvas[i]) continue;
        PeExport e{};
        e.name    = namesByOrd[i].empty()
                     ? (std::string("#") + std::to_string(i + ed.Base))
                     : namesByOrd[i];
        e.ordinal = i + ed.Base;
        // Forwarded exports' RVAs point inside the export directory range.
        if (funcRvas[i] >= dir.VirtualAddress &&
            funcRvas[i] <  dir.VirtualAddress + dir.Size) {
            e.forwarded = true;
        }
        e.address = base + funcRvas[i];
        out.push_back(std::move(e));
    }

    return out;
}

std::vector<PeImport> readImports(HANDLE process, Address base) {
    std::vector<PeImport> out;

    PeHeaders h = readPeHeaders(process, base);
    if (!h.ok) return out;

    const auto& dir = h.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return out;

    Address cur = base + dir.VirtualAddress;
    for (int guard = 0; guard < 4096; ++guard) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        if (!rpm(process, cur, desc)) break;
        if (!desc.Name && !desc.FirstThunk) break;

        PeImport imp{};
        imp.dll = readCString(process, base + desc.Name);

        // Prefer OriginalFirstThunk (import lookup table), fall back to
        // FirstThunk (IAT) — for bound images the lookup table may be
        // zeroed.
        Address thunk = base + (desc.OriginalFirstThunk
                                 ? desc.OriginalFirstThunk
                                 : desc.FirstThunk);

        for (int t = 0; t < 8192; ++t) {
            IMAGE_THUNK_DATA64 td{};
            if (!rpm(process, thunk, td)) break;
            if (!td.u1.AddressOfData) break;

            PeImport::Entry e{};
            if (td.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                e.ordinal   = static_cast<DWORD>(td.u1.Ordinal & 0xFFFF);
                e.name      = "#" + std::to_string(e.ordinal);
                e.byOrdinal = true;
            } else {
                // IMAGE_IMPORT_BY_NAME = WORD Hint + char Name[]
                e.name      = readCString(process,
                                            base + td.u1.AddressOfData + 2);
                e.byOrdinal = false;
            }
            imp.entries.push_back(std::move(e));
            thunk += sizeof(IMAGE_THUNK_DATA64);
        }

        out.push_back(std::move(imp));
        cur += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    return out;
}

} // namespace mdbg
