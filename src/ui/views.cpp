#include "views.h"

#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace mdbg::ui {

// RAII wrapper so each pane always pairs Begin/End even on early return.
struct Window {
    bool open;
    Window(const char* name, ImGuiWindowFlags flags = 0) {
        open = ImGui::Begin(name, nullptr, flags);
    }
    ~Window() { ImGui::End(); }
    operator bool() const { return open; }
    Window(const Window&) = delete;
    Window& operator=(const Window&) = delete;
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
static const char* stateString(DebuggerState s) {
    switch (s) {
        case DebuggerState::Idle:    return "idle";
        case DebuggerState::Running: return "running";
        case DebuggerState::Paused:  return "paused";
        case DebuggerState::Exited:  return "exited";
    }
    return "?";
}

static bool parseHex(const char* s, std::uint64_t& out) {
    if (!s) return false;
    while (*s == ' ') ++s;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!*s) return false;
    char* end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 16);
    if (end == s) return false;
    out = v;
    return true;
}

// ---------------------------------------------------------------------------
// control bar
// ---------------------------------------------------------------------------
void drawControlBar(UiState& ui, Debugger& dbg, const DebuggerSnapshot& snap) {
    Window w("Control");
    if (!w) return;

    if (ImGui::Button("Launch...")) ui.showLaunch = true;
    ImGui::SameLine();
    if (ImGui::Button("Attach...")) {
        ui.procs = ProcessList::enumerate();
        std::sort(ui.procs.begin(), ui.procs.end(),
                   [](auto& a, auto& b){ return a.name < b.name; });
        ui.showAttach = true;
    }
    ImGui::SameLine();
    ImGui::Dummy(ImVec2(12, 0)); ImGui::SameLine();

    const bool attached = dbg.isAttached();
    const bool paused   = snap.state == DebuggerState::Paused;

    ImGui::BeginDisabled(!attached || !paused);
    if (ImGui::Button("Run (F5)"))  dbg.run();
    ImGui::SameLine();
    if (ImGui::Button("Step Into (F7)"))  dbg.stepInto();
    ImGui::SameLine();
    if (ImGui::Button("Step Over (F8)"))  dbg.stepOver();
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(!attached || paused);
    if (ImGui::Button("Break"))   dbg.breakIn();
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("Detach"))  dbg.stop();
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::Dummy(ImVec2(16, 0)); ImGui::SameLine();
    ImGui::TextDisabled("state: %s   pid: %lu   rip: 0x%llX",
                         stateString(snap.state), snap.pid,
                         static_cast<unsigned long long>(snap.rip));

    // Keyboard shortcuts (process only when the attached+paused state allows)
    if (attached && paused) {
        if (ImGui::IsKeyPressed(ImGuiKey_F5)) dbg.run();
        if (ImGui::IsKeyPressed(ImGuiKey_F7)) dbg.stepInto();
        if (ImGui::IsKeyPressed(ImGuiKey_F8)) dbg.stepOver();
    }
}

// ---------------------------------------------------------------------------
// disasm
// ---------------------------------------------------------------------------
void drawDisasm(UiState& ui, Debugger& dbg, const DebuggerSnapshot& snap) {
    Window w("Disassembly");
    if (!w) return;

    if (ui.disasmPinAddr) {
        ImGui::TextColored(ImVec4(.7f,.85f,.95f,1),
                           "pinned 0x%llX",
                           (unsigned long long)ui.disasmPinAddr);
        ImGui::SameLine();
        if (ImGui::SmallButton("Follow RIP")) {
            ui.disasmPinAddr = 0;
            ui.disasmPinWindow.clear();
        }
        ImGui::SameLine(0, 24);
    }
    ImGui::SetNextItemWidth(160);
    ImGui::InputText("##goto", ui.disasmGotoBuf, sizeof(ui.disasmGotoBuf),
                      ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::SmallButton("Go")) {
        std::uint64_t a = 0;
        if (parseHex(ui.disasmGotoBuf, a)) ui.disasmPinAddr = (Address)a;
    }
    ImGui::Separator();

    Address     base = 0;
    const Byte* buf  = nullptr;
    std::size_t len  = 0;

    if (ui.disasmPinAddr) {
        constexpr std::size_t kWindow = 256;
        ui.disasmPinWindow.assign(kWindow, 0);
        bool ok = dbg.readMemory(ui.disasmPinAddr, ui.disasmPinWindow.data(),
                                   ui.disasmPinWindow.size());
        if (!ok) ui.disasmPinWindow.clear();
        base = ui.disasmPinAddr;
        buf  = ui.disasmPinWindow.data();
        len  = ui.disasmPinWindow.size();
    } else {
        base = snap.ripWindowBase;
        buf  = snap.ripWindow.data();
        len  = snap.ripWindow.size();
    }

    if (len == 0) {
        ImGui::TextDisabled("(no instruction stream — attach and pause)");
        return;
    }

    ui.disasmCache = ui.disasm.decode(base, buf, len, 64);

    auto bps = dbg.breakpoints();
    auto isBP = [&](Address a) {
        for (const auto& b : bps) if (b.address == a && b.enabled) return true;
        return false;
    };

    if (ImGui::BeginTable("##dasm", 4,
                           ImGuiTableFlags_BordersInnerV |
                           ImGuiTableFlags_RowBg |
                           ImGuiTableFlags_ScrollY |
                           ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("", 0, 16);
        ImGui::TableSetupColumn("Address",     0, 140);
        ImGui::TableSetupColumn("Bytes",       0, 160);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& ins : ui.disasmCache) {
            ImGui::TableNextRow();
            const bool here = (ins.address == snap.rip);
            const bool bp   = isBP(ins.address);

            if (here) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                        IM_COL32(60, 60, 80, 110));
            } else if (bp) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                        IM_COL32(80, 40, 40, 90));
            }

            ImGui::TableSetColumnIndex(0);
            if (bp)   ImGui::TextColored(ImVec4(1,.4f,.4f,1), "*");
            else if (here) ImGui::TextColored(ImVec4(.6f,.9f,1,1), ">");

            ImGui::TableSetColumnIndex(1);
            char idbuf[64];
            std::snprintf(idbuf, sizeof(idbuf), "0x%016llX##%llu",
                          (unsigned long long)ins.address,
                          (unsigned long long)ins.address);
            if (ImGui::Selectable(idbuf, false,
                                    ImGuiSelectableFlags_SpanAllColumns |
                                    ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(0)) {
                    // Toggle BP on double-click
                    if (bp) {
                        for (const auto& b : bps) if (b.address == ins.address) {
                            dbg.removeBreakpoint(b.id); break;
                        }
                    } else {
                        dbg.addBreakpoint(ins.address);
                    }
                }
            }

            ImGui::TableSetColumnIndex(2);
            ImGui::TextDisabled("%s", ins.bytes.c_str());

            ImGui::TableSetColumnIndex(3);
            ImVec4 col(.87f, .87f, .88f, 1);
            if (ins.isCall)        col = ImVec4(.6f, .9f, .6f, 1);
            else if (ins.isReturn) col = ImVec4(.95f,.75f,.55f,1);
            else if (ins.isJump)   col = ImVec4(.7f, .8f, 1.f, 1);
            ImGui::TextColored(col, "%s", ins.text.c_str());
        }
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------------------------
// registers
// ---------------------------------------------------------------------------
void drawRegisters(const DebuggerSnapshot& snap) {
    Window w("Registers");
    if (!w) return;

    ImGui::TextDisabled("tid %lu", snap.currentTid);
    ImGui::Separator();

    if (snap.state == DebuggerState::Idle || snap.state == DebuggerState::Exited) {
        ImGui::TextDisabled("(no thread context)");
        return;
    }

    struct Reg { const char* name; DWORD64 val; };
    const auto& c = snap.ctx;
    const Reg regs[] = {
        {"RAX", c.Rax}, {"RBX", c.Rbx}, {"RCX", c.Rcx}, {"RDX", c.Rdx},
        {"RSI", c.Rsi}, {"RDI", c.Rdi}, {"RBP", c.Rbp}, {"RSP", c.Rsp},
        {"R8",  c.R8 }, {"R9",  c.R9 }, {"R10", c.R10}, {"R11", c.R11},
        {"R12", c.R12}, {"R13", c.R13}, {"R14", c.R14}, {"R15", c.R15},
        {"RIP", c.Rip}, {"RFL", c.EFlags},
    };

    if (ImGui::BeginTable("##regs", 2,
                           ImGuiTableFlags_BordersInnerV |
                           ImGuiTableFlags_RowBg |
                           ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("Reg",   0, 40);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        for (const auto& r : regs) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(ImVec4(.7f,.7f,.75f,1), "%s", r.name);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("0x%016llX", (unsigned long long)r.val);
        }
        ImGui::EndTable();
    }

    // Flag bits (EFlags common ones)
    const DWORD eflags = (DWORD)(c.EFlags);
    ImGui::Dummy(ImVec2(0, 4));
    ImGui::TextDisabled(
        "CF=%u PF=%u ZF=%u SF=%u OF=%u DF=%u IF=%u TF=%u",
        (unsigned)!!(eflags & 0x001),
        (unsigned)!!(eflags & 0x004),
        (unsigned)!!(eflags & 0x040),
        (unsigned)!!(eflags & 0x080),
        (unsigned)!!(eflags & 0x800),
        (unsigned)!!(eflags & 0x400),
        (unsigned)!!(eflags & 0x200),
        (unsigned)!!(eflags & 0x100));
}

// ---------------------------------------------------------------------------
// call stack
// ---------------------------------------------------------------------------
void drawCallStack(UiState& ui, Debugger& dbg, const DebuggerSnapshot& snap) {
    Window w("Call Stack");
    if (!w) return;

    ImGui::TextDisabled("tid %lu", snap.currentTid);
    ImGui::Separator();

    const bool paused = snap.state == DebuggerState::Paused;
    if (!paused) {
        ImGui::TextDisabled("(available while paused)");
        ui.stackCache.clear();
        ui.stackCacheRip = 0;
        ui.stackCacheTid = 0;
        return;
    }

    // Re-walk only when RIP or thread actually changed — otherwise the UI
    // would hit DbgHelp every frame while the user is just scrolling.
    if (snap.rip != ui.stackCacheRip || snap.currentTid != ui.stackCacheTid) {
        ui.stackCache = dbg.callStack();
        ui.stackCacheRip = snap.rip;
        ui.stackCacheTid = snap.currentTid;
    }

    if (ui.stackCache.empty()) {
        ImGui::TextDisabled("(empty — symbols/unwind info missing?)");
        return;
    }

    if (ImGui::BeginTable("##cs", 3,
                           ImGuiTableFlags_BordersInnerV |
                           ImGuiTableFlags_RowBg |
                           ImGuiTableFlags_ScrollY |
                           ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("#",       0, 24);
        ImGui::TableSetupColumn("Address", 0, 140);
        ImGui::TableSetupColumn("Function",
                                 ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& f : ui.stackCache) {
            ImGui::TableNextRow();
            ImGui::PushID(f.index);
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%d", f.index);

            ImGui::TableSetColumnIndex(1);
            char idbuf[48];
            std::snprintf(idbuf, sizeof(idbuf), "0x%016llX##csrow",
                           (unsigned long long)f.address);
            bool clicked = ImGui::Selectable(idbuf, false,
                                               ImGuiSelectableFlags_SpanAllColumns |
                                               ImGuiSelectableFlags_AllowDoubleClick);
            if (clicked && ImGui::IsMouseDoubleClicked(0)) {
                ui.disasmPinAddr = f.address;
            }

            ImGui::TableSetColumnIndex(2);
            std::string line;
            if (f.sym.hasModule) {
                line += wide_to_utf8(f.sym.moduleName);
                line += "!";
            }
            if (f.sym.hasSymbol) {
                line += f.sym.symbolName;
                if (f.sym.displacement) {
                    char off[32];
                    std::snprintf(off, sizeof(off), "+0x%llX",
                                  (unsigned long long)f.sym.displacement);
                    line += off;
                }
            } else {
                char off[32];
                std::snprintf(off, sizeof(off), "0x%llX",
                              (unsigned long long)f.address);
                line += off;
            }
            ImGui::TextColored(f.sym.hasSymbol
                                ? ImVec4(.85f,.9f,.75f,1)
                                : ImVec4(.7f,.7f,.72f,1),
                                "%s", line.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------
void drawMemory(UiState& ui, Debugger& dbg) {
    Window w("Memory");
    if (!w) return;

    ImGui::SetNextItemWidth(220);
    ImGui::InputText("Address", ui.memAddrBuf, sizeof(ui.memAddrBuf),
                      ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80);
    ImGui::InputInt("Rows", &ui.memRows);
    if (ui.memRows < 1)  ui.memRows = 1;
    if (ui.memRows > 64) ui.memRows = 64;
    ImGui::SameLine();
    if (ImGui::Button("Read")) {
        std::uint64_t addr = 0;
        if (parseHex(ui.memAddrBuf, addr)) {
            ui.memAddr = static_cast<Address>(addr);
            ui.memBuf.assign(ui.memRows * 16, 0);
            dbg.readMemory(ui.memAddr, ui.memBuf.data(), ui.memBuf.size());
        }
    }

    if (ui.memBuf.empty()) {
        ImGui::TextDisabled("(enter an address and click Read)");
        return;
    }

    ImGui::BeginChild("##memdump", ImVec2(0, 0), false);
    for (int row = 0; row < ui.memRows; ++row) {
        std::size_t off = row * 16;
        if (off >= ui.memBuf.size()) break;
        Address rowAddr = ui.memAddr + off;
        ImGui::TextColored(ImVec4(.7f,.7f,.75f,1), "%016llX:",
                           (unsigned long long)rowAddr);
        ImGui::SameLine();
        char hex[64]{}, ascii[20]{};
        int h = 0, a = 0;
        for (int i = 0; i < 16 && off + i < ui.memBuf.size(); ++i) {
            Byte b = ui.memBuf[off + i];
            h += std::snprintf(hex + h, sizeof(hex) - h, "%02X ", b);
            ascii[a++] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
        }
        ImGui::Text("%-48s |%s|", hex, ascii);
    }
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// breakpoints
// ---------------------------------------------------------------------------
static const char* condName(HwCondition c) {
    switch (c) {
        case HwCondition::Execute:   return "exec";
        case HwCondition::Write:     return "write";
        case HwCondition::ReadWrite: return "r/w";
    }
    return "?";
}

static int sizeToBytes(HwSize s) { return static_cast<int>(s); }

void drawBreakpoints(UiState& ui, Debugger& dbg) {
    Window w("Breakpoints");
    if (!w) return;

    ImGui::Text("Software (INT3)");
    ImGui::SetNextItemWidth(220);
    ImGui::InputText("##addbp", ui.addBpBuf, sizeof(ui.addBpBuf),
                      ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("Add SW BP")) {
        std::uint64_t addr = 0;
        if (parseHex(ui.addBpBuf, addr) && dbg.isAttached()) {
            dbg.addBreakpoint(static_cast<Address>(addr));
        }
    }

    auto bps = dbg.breakpoints();
    if (ImGui::BeginTable("##bps", 5,
                           ImGuiTableFlags_BordersInnerV |
                           ImGuiTableFlags_RowBg |
                           ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("ID",      0, 40);
        ImGui::TableSetupColumn("Address", 0, 160);
        ImGui::TableSetupColumn("On",      0, 30);
        ImGui::TableSetupColumn("Script",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("",        0, 70);
        ImGui::TableHeadersRow();
        for (const auto& bp : bps) {
            ImGui::PushID((int)bp.id);
            ImGui::TableNextRow();

            const bool selected = (ui.selectedBpId == bp.id);
            if (selected) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                        IM_COL32(60, 60, 80, 110));
            }

            ImGui::TableSetColumnIndex(0);
            char lbl[16]; std::snprintf(lbl, sizeof(lbl), "%u##sel", bp.id);
            if (ImGui::Selectable(lbl, selected,
                                    ImGuiSelectableFlags_SpanAllColumns)) {
                ui.selectedBpId = bp.id;
                std::strncpy(ui.bpScriptBuf, bp.script.c_str(),
                              sizeof(ui.bpScriptBuf) - 1);
                ui.bpScriptBuf[sizeof(ui.bpScriptBuf) - 1] = '\0';
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::Text("0x%016llX", (unsigned long long)bp.address);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text(bp.enabled ? "y" : "n");
            ImGui::TableSetColumnIndex(3);
            if (bp.script.empty())
                ImGui::TextDisabled("(none)");
            else
                ImGui::TextColored(ImVec4(.8f,.9f,.75f,1), "%.60s",
                                    bp.script.c_str());
            ImGui::TableSetColumnIndex(4);
            if (ImGui::SmallButton("Remove")) {
                dbg.removeBreakpoint(bp.id);
                if (ui.selectedBpId == bp.id) {
                    ui.selectedBpId = 0;
                    ui.bpScriptBuf[0] = '\0';
                }
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    // Script editor for the selected BP.
    if (ui.selectedBpId) {
        ImGui::Dummy(ImVec2(0, 6));
        ImGui::TextDisabled("Condition script for BP #%u (Lua — return a boolean)",
                             ui.selectedBpId);
        ImGui::InputTextMultiline("##bpscript",
                                   ui.bpScriptBuf, sizeof(ui.bpScriptBuf),
                                   ImVec2(-FLT_MIN, 60),
                                   ImGuiInputTextFlags_AllowTabInput);
        if (ImGui::Button("Save script")) {
            dbg.setBreakpointScript(ui.selectedBpId,
                                      std::string(ui.bpScriptBuf));
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear script")) {
            ui.bpScriptBuf[0] = '\0';
            dbg.setBreakpointScript(ui.selectedBpId, std::string());
        }
        ImGui::SameLine();
        ImGui::TextDisabled("example: return dbg.rax() == 0x42");
    }

    ImGui::Dummy(ImVec2(0, 8));
    ImGui::Text("Hardware breakpoints (DR0-DR3, 4 slots max)");
    ImGui::Separator();

    ImGui::SetNextItemWidth(220);
    ImGui::InputText("##addhbp", ui.addHwBpBuf, sizeof(ui.addHwBpBuf),
                      ImGuiInputTextFlags_CharsHexadecimal);

    ImGui::SameLine();
    ImGui::SetNextItemWidth(90);
    const char* condItems[] = {"exec", "write", "r/w"};
    ImGui::Combo("##hbpcond", &ui.hwBpCond, condItems, IM_ARRAYSIZE(condItems));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60);
    const char* sizeItems[] = {"1", "2", "4", "8"};
    ImGui::Combo("##hbpsize", &ui.hwBpSize, sizeItems, IM_ARRAYSIZE(sizeItems));
    ImGui::SameLine();
    if (ImGui::Button("Add HW BP")) {
        std::uint64_t addr = 0;
        if (parseHex(ui.addHwBpBuf, addr) && dbg.isAttached()) {
            HwCondition c = (ui.hwBpCond == 0) ? HwCondition::Execute :
                             (ui.hwBpCond == 1) ? HwCondition::Write :
                                                    HwCondition::ReadWrite;
            HwSize s = (ui.hwBpSize == 0) ? HwSize::Byte :
                        (ui.hwBpSize == 1) ? HwSize::Word :
                        (ui.hwBpSize == 2) ? HwSize::Dword : HwSize::Qword;
            HwBpId id = dbg.addHwBreakpoint(static_cast<Address>(addr), c, s);
            if (!id) {
                // Common causes: all 4 slots used, or misaligned data BP.
                ui.log.push_back("[!] HBP add failed (slots full or misaligned)");
            }
        }
    }

    auto hbps = dbg.hwBreakpoints();
    if (ImGui::BeginTable("##hbps", 6,
                           ImGuiTableFlags_BordersInnerV |
                           ImGuiTableFlags_RowBg |
                           ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("ID",      0, 40);
        ImGui::TableSetupColumn("Slot",    0, 40);
        ImGui::TableSetupColumn("Address", 0, 160);
        ImGui::TableSetupColumn("Cond",    0, 60);
        ImGui::TableSetupColumn("Size",    0, 40);
        ImGui::TableSetupColumn("",        ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& bp : hbps) {
            ImGui::PushID((int)bp.id + 10000);
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("%u", bp.id);
            ImGui::TableSetColumnIndex(1); ImGui::Text("DR%d", bp.slot);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("0x%016llX", (unsigned long long)bp.addr);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(ImVec4(.7f,.85f,.95f,1), "%s", condName(bp.cond));
            ImGui::TableSetColumnIndex(4); ImGui::Text("%d", sizeToBytes(bp.size));
            ImGui::TableSetColumnIndex(5);
            if (ImGui::SmallButton("Remove")) {
                dbg.removeHwBreakpoint(bp.id);
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------------------------
// modules
// ---------------------------------------------------------------------------
void drawModules(UiState& ui, Debugger& dbg) {
    Window w("Modules");
    if (!w) return;

    // Lazily seed the sym-path edit box with whatever DbgHelp is using.
    if (!ui.symPathLoaded && dbg.isAttached()) {
        std::string s = wide_to_utf8(dbg.symSearchPath());
        std::strncpy(ui.symPathBuf, s.c_str(), sizeof(ui.symPathBuf) - 1);
        ui.symPathLoaded = true;
    }

    if (ImGui::CollapsingHeader("Symbol search path (symsrv syntax)")) {
        ImGui::TextDisabled("srv*<cache>*<url>  — cache then fetch");
        ImGui::SetNextItemWidth(-120);
        ImGui::InputText("##sympath", ui.symPathBuf, sizeof(ui.symPathBuf));
        ImGui::SameLine();
        if (ImGui::Button("Apply")) {
            dbg.setSymSearchPath(utf8_to_wide(ui.symPathBuf));
        }
        if (ImGui::Button("Reset to default")) {
            auto def = wide_to_utf8(Symbols::defaultSearchPath());
            std::strncpy(ui.symPathBuf, def.c_str(), sizeof(ui.symPathBuf) - 1);
            dbg.setSymSearchPath(Symbols::defaultSearchPath());
        }
    }

    auto mods = dbg.modules();
    if (mods.empty()) {
        ImGui::TextDisabled("(no modules — attach first)");
        return;
    }

    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##mfilter", "filter...",
                              ui.moduleFilter, sizeof(ui.moduleFilter));

    float listH = ImGui::GetContentRegionAvail().y * 0.35f;
    ImGui::BeginChild("##mlist", ImVec2(0, listH), true);
    if (ImGui::BeginTable("##mt", 3,
                           ImGuiTableFlags_BordersInnerV |
                           ImGuiTableFlags_RowBg |
                           ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("Base",   0, 140);
        ImGui::TableSetupColumn("Size",   0, 80);
        ImGui::TableSetupColumn("Name",   ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& m : mods) {
            std::string nm = wide_to_utf8(m.name);
            if (ui.moduleFilter[0] && !std::strstr(nm.c_str(), ui.moduleFilter))
                continue;
            ImGui::TableNextRow();
            char idbuf[64];
            std::snprintf(idbuf, sizeof(idbuf), "0x%llX##mod",
                           (unsigned long long)m.base);
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(idbuf,
                                    ui.selectedModuleBase == m.base,
                                    ImGuiSelectableFlags_SpanAllColumns)) {
                ui.selectedModuleBase = m.base;
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("0x%06lX", (unsigned long)m.size);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", nm.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    if (!ui.selectedModuleBase) {
        ImGui::TextDisabled("(select a module to see imports/exports)");
        return;
    }

    // Lazy populate caches
    if (ui.selectedModuleBase != ui.importsCacheBase) {
        ui.importsCache     = dbg.moduleImports(ui.selectedModuleBase);
        ui.importsCacheBase = ui.selectedModuleBase;
    }
    if (ui.selectedModuleBase != ui.exportsCacheBase) {
        ui.exportsCache     = dbg.moduleExports(ui.selectedModuleBase);
        ui.exportsCacheBase = ui.selectedModuleBase;
    }

    if (ImGui::BeginTabBar("##iotabs")) {
        if (ImGui::BeginTabItem("Exports")) {
            if (ui.exportsCache.empty()) {
                ImGui::TextDisabled("(no exports)");
            } else if (ImGui::BeginTable("##ex", 3,
                                          ImGuiTableFlags_BordersInnerV |
                                          ImGuiTableFlags_RowBg |
                                          ImGuiTableFlags_ScrollY |
                                          ImGuiTableFlags_SizingFixedFit)) {
                ImGui::TableSetupColumn("Ordinal", 0, 60);
                ImGui::TableSetupColumn("Address", 0, 140);
                ImGui::TableSetupColumn("Name",
                                         ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                for (const auto& e : ui.exportsCache) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%lu", (unsigned long)e.ordinal);
                    ImGui::TableSetColumnIndex(1);
                    char idbuf[48];
                    std::snprintf(idbuf, sizeof(idbuf), "0x%016llX##ex",
                                   (unsigned long long)e.address);
                    if (ImGui::Selectable(idbuf, false,
                                            ImGuiSelectableFlags_SpanAllColumns |
                                            ImGuiSelectableFlags_AllowDoubleClick)
                        && ImGui::IsMouseDoubleClicked(0)) {
                        ui.disasmPinAddr = e.address;
                    }
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextColored(e.forwarded
                                        ? ImVec4(.9f,.7f,.4f,1)
                                        : ImVec4(.85f,.9f,.75f,1),
                                        "%s%s", e.name.c_str(),
                                        e.forwarded ? " (fwd)" : "");
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Imports")) {
            if (ui.importsCache.empty()) {
                ImGui::TextDisabled("(no imports)");
            } else {
                for (const auto& imp : ui.importsCache) {
                    if (ImGui::TreeNode(imp.dll.c_str(), "%s  (%zu)",
                                         imp.dll.c_str(),
                                         imp.entries.size())) {
                        for (const auto& e : imp.entries) {
                            ImGui::BulletText("%s", e.name.c_str());
                        }
                        ImGui::TreePop();
                    }
                }
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

// ---------------------------------------------------------------------------
// lua eval pane
// ---------------------------------------------------------------------------
void drawLua(UiState& ui, Debugger& dbg) {
    Window w("Lua");
    if (!w) return;

    if (ui.luaInput.empty()) {
        constexpr std::size_t kBuf = 16 * 1024;
        ui.luaInput.assign(kBuf, '\0');
        const char* sample =
            "-- bindings: dbg.readU8/16/32/64(addr), dbg.writeU8/16/32/64(addr, v)\n"
            "-- dbg.rip(), dbg.rax()..., dbg.addBp(addr), dbg.continueExec()\n"
            "-- print(...) and dbg.log(s) go to the output below.\n\n"
            "print(string.format(\"rip = 0x%X\", dbg.rip()))\n";
        std::memcpy(ui.luaInput.data(), sample, std::strlen(sample));
    }

    float h = ImGui::GetContentRegionAvail().y;
    ImGui::InputTextMultiline("##luasrc",
                               ui.luaInput.data(), ui.luaInput.size(),
                               ImVec2(-FLT_MIN, h * 0.5f),
                               ImGuiInputTextFlags_AllowTabInput);

    if (ImGui::Button("Run (Ctrl+Enter)") ||
        (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) &&
         ImGui::IsKeyPressed(ImGuiKey_Enter))) {
        std::string status = dbg.scripting().eval(ui.luaInput.data());
        for (auto& l : dbg.scripting().drainOutput()) {
            ui.luaOutput += l;
            ui.luaOutput += '\n';
        }
        if (status != "ok") {
            ui.luaOutput += status;
            ui.luaOutput += '\n';
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear output")) ui.luaOutput.clear();
    ImGui::SameLine();
    ImGui::TextDisabled("%zu bytes", ui.luaOutput.size());

    ImGui::Separator();
    ImGui::BeginChild("##luaout", ImVec2(0, 0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(ui.luaOutput.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20)
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// log
// ---------------------------------------------------------------------------
void drawLog(UiState& ui) {
    Window w("Log");
    if (!w) return;

    ImGui::BeginChild("##logtxt", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto& line : ui.log) {
        ImGui::TextUnformatted(line.c_str());
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20)
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// launch dialog
// ---------------------------------------------------------------------------
void drawLaunchDialog(UiState& ui, Debugger& dbg) {
    if (!ui.showLaunch) return;

    ImGui::OpenPopup("Launch debuggee");
    ImGui::SetNextWindowSize(ImVec2(520, 180), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("Launch debuggee", &ui.showLaunch,
                                ImGuiWindowFlags_NoResize)) {
        ImGui::TextDisabled("Full path to executable:");
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputText("##exepath", ui.launchPath, sizeof(ui.launchPath));
        ImGui::TextDisabled("Arguments (optional):");
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputText("##exeargs", ui.launchArgs, sizeof(ui.launchArgs));

        ImGui::Dummy(ImVec2(0, 8));
        if (ImGui::Button("Launch", ImVec2(120, 0))) {
            if (ui.launchPath[0]) {
                dbg.launch(utf8_to_wide(ui.launchPath), utf8_to_wide(ui.launchArgs));
                ui.showLaunch = false;
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            ui.showLaunch = false;
        }
        ImGui::EndPopup();
    }
}

// ---------------------------------------------------------------------------
// attach dialog
// ---------------------------------------------------------------------------
void drawAttachDialog(UiState& ui, Debugger& dbg) {
    if (!ui.showAttach) return;

    ImGui::OpenPopup("Attach to process");
    ImGui::SetNextWindowSize(ImVec2(520, 440), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("Attach to process", &ui.showAttach)) {
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputText("##filter", ui.procFilter, sizeof(ui.procFilter));

        ImGui::BeginChild("##plist", ImVec2(0, -40), true);
        for (int i = 0; i < (int)ui.procs.size(); ++i) {
            const auto& e = ui.procs[i];
            std::string name = wide_to_utf8(e.name);
            if (ui.procFilter[0]) {
                if (!std::strstr(name.c_str(), ui.procFilter)) continue;
            }
            char label[256];
            std::snprintf(label, sizeof(label), "%-6lu  %s##%d", e.pid,
                          name.c_str(), i);
            if (ImGui::Selectable(label, ui.procSelected == i,
                                   ImGuiSelectableFlags_AllowDoubleClick)) {
                ui.procSelected = i;
                if (ImGui::IsMouseDoubleClicked(0)) {
                    dbg.attach(e.pid);
                    ui.showAttach = false;
                }
            }
        }
        ImGui::EndChild();

        ImGui::BeginDisabled(ui.procSelected < 0);
        if (ImGui::Button("Attach", ImVec2(120, 0))) {
            if (ui.procSelected >= 0 && ui.procSelected < (int)ui.procs.size()) {
                dbg.attach(ui.procs[ui.procSelected].pid);
                ui.showAttach = false;
            }
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Refresh", ImVec2(120, 0))) {
            ui.procs = ProcessList::enumerate();
            std::sort(ui.procs.begin(), ui.procs.end(),
                       [](auto& a, auto& b){ return a.name < b.name; });
            ui.procSelected = -1;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            ui.showAttach = false;
        }
        ImGui::EndPopup();
    }
}

} // namespace mdbg::ui
