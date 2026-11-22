// disasm.h — Zydis-backed x64 disassembler wrapper
#pragma once

#include "common.h"

namespace mdbg {

struct DecodedInsn {
    Address     address{};
    std::size_t length{};
    std::string text;      // formatted asm (Intel syntax)
    std::string bytes;     // hex byte dump
    bool        isBranch{}; // any control-flow transfer
    bool        isCall{};
    bool        isReturn{};
    bool        isJump{};
    // Only meaningful for direct branches; 0 otherwise.
    Address     branchTarget{};
};

class Disassembler {
public:
    Disassembler();

    // Decode up to `maxInsn` instructions starting at `address` from `buf`.
    // Undecodable bytes render as `db 0xNN` (1-byte entries) so the stream
    // never desyncs the UI.
    std::vector<DecodedInsn> decode(Address address,
                                     const Byte* buf, std::size_t len,
                                     std::size_t maxInsn = 64);

    // Length of the single instruction starting at `buf`. Returns 0 on
    // failure. Used by step-over to place a temp BP past a CALL.
    std::size_t insnLength(const Byte* buf, std::size_t len);
};

} // namespace mdbg
