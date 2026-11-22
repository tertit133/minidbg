#include "disasm.h"

#include <Zydis/Zydis.h>

#include <cstdio>

namespace mdbg {

Disassembler::Disassembler() = default;

std::vector<DecodedInsn> Disassembler::decode(Address address,
                                               const Byte* buf, std::size_t len,
                                               std::size_t maxInsn) {
    std::vector<DecodedInsn> out;
    out.reserve(maxInsn);

    ZydisDecoder   decoder{};
    ZydisFormatter formatter{};
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    std::size_t offset = 0;
    while (offset < len && out.size() < maxInsn) {
        ZydisDecodedInstruction ins{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};

        ZyanStatus st = ZydisDecoderDecodeFull(&decoder,
                                                buf + offset, len - offset,
                                                &ins, ops);
        if (!ZYAN_SUCCESS(st)) {
            // Undecodable byte: emit as `db 0xNN` and keep going.
            char hex[8];
            std::snprintf(hex, sizeof(hex), "%02X", buf[offset]);
            char txt[16];
            std::snprintf(txt, sizeof(txt), "db 0x%02X", buf[offset]);
            out.push_back({ address + offset, 1, txt, hex,
                             false, false, false, false, 0 });
            offset += 1;
            continue;
        }

        char text[256];
        ZydisFormatterFormatInstruction(&formatter, &ins, ops,
                                         ins.operand_count_visible,
                                         text, sizeof(text),
                                         address + offset, nullptr);

        std::string hex;
        hex.reserve(ins.length * 3);
        for (std::size_t i = 0; i < ins.length; ++i) {
            char b[4];
            std::snprintf(b, sizeof(b), "%02X ", buf[offset + i]);
            hex += b;
        }
        if (!hex.empty()) hex.pop_back();

        DecodedInsn d{};
        d.address  = address + offset;
        d.length   = ins.length;
        d.text     = text;
        d.bytes    = std::move(hex);
        d.isCall   = (ins.meta.category == ZYDIS_CATEGORY_CALL);
        d.isReturn = (ins.meta.category == ZYDIS_CATEGORY_RET);
        d.isJump   = (ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR
                      || ins.meta.category == ZYDIS_CATEGORY_COND_BR);
        d.isBranch = d.isCall || d.isReturn || d.isJump;

        // Resolve direct-branch targets (immediate operand), best-effort.
        if ((d.isCall || d.isJump) && ins.operand_count_visible > 0) {
            const auto& op = ops[0];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                ZyanU64 target = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op,
                                                          address + offset, &target))) {
                    d.branchTarget = static_cast<Address>(target);
                }
            }
        }

        out.push_back(std::move(d));
        offset += ins.length;
    }
    return out;
}

std::size_t Disassembler::insnLength(const Byte* buf, std::size_t len) {
    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction ins{};
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buf, len, &ins, ops))) return 0;
    return ins.length;
}

} // namespace mdbg
