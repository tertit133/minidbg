// app.h — Win32 window + DX11 + ImGui host for MiniDbg
#pragma once

#include "common.h"
#include "debugger.h"

#include <d3d11.h>

namespace mdbg::ui {

struct UiState {
    // Shared log buffer (ring, append-only from drainLog()).
    std::vector<std::string> log;
    std::size_t              logLimit{4096};

    // Launch dialog
    bool    showLaunch{false};
    char    launchPath[1024]{};
    char    launchArgs[512]{};

    // Attach dialog
    bool    showAttach{false};
    std::vector<ProcessList::Entry> procs;
    int     procSelected{-1};
    char    procFilter[64]{};

    // Memory view
    char     memAddrBuf[32] = "0";
    Bytes    memBuf;
    Address  memAddr{};
    int      memRows{16};

    // Add-BP (software) field
    char    addBpBuf[32] = "0x";

    // Conditional-BP script editor
    std::uint32_t selectedBpId{};
    char          bpScriptBuf[2048]{};

    // Add-HBP (hardware) fields
    char    addHwBpBuf[32] = "0x";
    int     hwBpCond{0};   // 0=Execute, 1=Write, 2=ReadWrite
    int     hwBpSize{0};   // 0=1b, 1=2b, 2=4b, 3=8b

    // Disasm decoded cache (invalidated each frame)
    std::vector<DecodedInsn> disasmCache;
    Disassembler             disasm;

    // Disasm pin: when non-zero, disasm view reads from this address
    // instead of RIP. "Follow RIP" clears it.
    Address                  disasmPinAddr{};
    char                     disasmGotoBuf[32] = "0x";
    Bytes                    disasmPinWindow;

    // Call-stack cache: only re-walked when RIP changes (walking is cheap
    // but LOAD_LINES + SymFromAddr adds up over many frames).
    std::vector<StackFrame>  stackCache;
    Address                  stackCacheRip{};
    DWORD                    stackCacheTid{};

    // Modules pane
    Address                  selectedModuleBase{};
    std::vector<PeImport>    importsCache;
    std::vector<PeExport>    exportsCache;
    Address                  importsCacheBase{};
    Address                  exportsCacheBase{};
    char                     moduleFilter[64]{};
    char                     symPathBuf[2048]{};
    bool                     symPathLoaded{false};

    // Lua pane
    std::vector<char>        luaInput;      // dynamic — ImGui multi-line
    std::string              luaOutput;
};

class App {
public:
    bool init(HINSTANCE hInst);
    void run();
    void shutdown();

    void bind(Debugger* dbg) { m_dbg = dbg; }

private:
    void frame();
    void present();
    void makeRenderTarget();
    void dropRenderTarget();

    static LRESULT CALLBACK wndProcThunk(HWND, UINT, WPARAM, LPARAM);
    LRESULT handleMessage(HWND, UINT, WPARAM, LPARAM);

    HWND                    m_hwnd{};
    ID3D11Device*           m_dev{};
    ID3D11DeviceContext*    m_ctx{};
    IDXGISwapChain*         m_sc{};
    ID3D11RenderTargetView* m_rtv{};

    bool      m_resizePending{};
    UINT      m_resizeW{}, m_resizeH{};
    bool      m_dockLayoutBuilt{false};

    Debugger* m_dbg{};
    UiState   m_ui;

    void buildDefaultDockLayoutIfFirstRun(ImGuiID dockId);
};

} // namespace mdbg::ui
