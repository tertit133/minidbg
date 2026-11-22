#include "app.h"

#include "theme.h"
#include "views.h"

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include <dxgi.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace mdbg::ui {

static App* g_app = nullptr;

LRESULT CALLBACK App::wndProcThunk(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (g_app) return g_app->handleMessage(h, m, w, l);
    return ::DefWindowProcW(h, m, w, l);
}

LRESULT App::handleMessage(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (ImGui_ImplWin32_WndProcHandler(h, m, w, l)) return 0;

    switch (m) {
        case WM_SIZE:
            if (m_dev && w != SIZE_MINIMIZED) {
                m_resizeW = LOWORD(l);
                m_resizeH = HIWORD(l);
                m_resizePending = true;
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((w & 0xFFF0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProcW(h, m, w, l);
}

bool App::init(HINSTANCE hInst) {
    g_app = this;

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = wndProcThunk;
    wc.hInstance     = hInst;
    wc.hCursor       = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW);
    wc.lpszClassName = L"MiniDbgWindow";
    ::RegisterClassExW(&wc);

    m_hwnd = ::CreateWindowExW(
        0, wc.lpszClassName, L"MiniDbg — x64 debugger",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1400, 900,
        nullptr, nullptr, hInst, nullptr);
    if (!m_hwnd) return false;

    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount       = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage       = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow      = m_hwnd;
    sd.SampleDesc.Count  = 1;
    sd.Windowed          = TRUE;
    sd.SwapEffect        = DXGI_SWAP_EFFECT_FLIP_DISCARD;

    D3D_FEATURE_LEVEL fl;
    HRESULT hr = ::D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        nullptr, 0, D3D11_SDK_VERSION, &sd, &m_sc,
        &m_dev, &fl, &m_ctx);
    if (FAILED(hr)) return false;
    makeRenderTarget();

    ::ShowWindow(m_hwnd, SW_SHOW);
    ::UpdateWindow(m_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard
                                 | ImGuiConfigFlags_DockingEnable;
    applyGrayTheme();
    ImGui_ImplWin32_Init(m_hwnd);
    ImGui_ImplDX11_Init(m_dev, m_ctx);

    // Default launch-path to empty so views show a hint.
    m_ui.launchPath[0] = '\0';

    return true;
}

void App::makeRenderTarget() {
    ID3D11Texture2D* bb = nullptr;
    m_sc->GetBuffer(0, IID_PPV_ARGS(&bb));
    if (bb) {
        m_dev->CreateRenderTargetView(bb, nullptr, &m_rtv);
        bb->Release();
    }
}

void App::dropRenderTarget() {
    if (m_rtv) { m_rtv->Release(); m_rtv = nullptr; }
}

void App::run() {
    MSG msg{};
    bool done = false;
    while (!done) {
        while (::PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (m_resizePending) {
            dropRenderTarget();
            m_sc->ResizeBuffers(0, m_resizeW, m_resizeH, DXGI_FORMAT_UNKNOWN, 0);
            makeRenderTarget();
            m_resizePending = false;
        }

        frame();
        present();
    }
}

void App::frame() {
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    // Drain fresh log lines from the debugger once per frame.
    if (m_dbg) {
        auto lines = m_dbg->drainLog();
        for (auto& ln : lines) m_ui.log.push_back(std::move(ln));
        if (m_ui.log.size() > m_ui.logLimit) {
            m_ui.log.erase(m_ui.log.begin(),
                            m_ui.log.begin() + (m_ui.log.size() - m_ui.logLimit));
        }
        m_dbg->drainEvents();  // reserved for future wiring
    }

    DebuggerSnapshot snap{};
    if (m_dbg) snap = m_dbg->snapshot();

    // Dockspace covering the whole main viewport.
    ImGuiID dockId = ImGui::DockSpaceOverViewport(
        ImGui::GetMainViewport(), ImGuiDockNodeFlags_PassthruCentralNode);

    buildDefaultDockLayoutIfFirstRun(dockId);

    // Each pane is its own top-level window — the user can drag, split,
    // float or tab them freely. Layout saves to imgui.ini.
    drawControlBar (m_ui, *m_dbg, snap);
    drawDisasm     (m_ui, *m_dbg, snap);
    drawRegisters  (snap);
    drawCallStack  (m_ui, *m_dbg, snap);
    drawMemory     (m_ui, *m_dbg);
    drawBreakpoints(m_ui, *m_dbg);
    drawModules    (m_ui, *m_dbg);
    drawLua        (m_ui, *m_dbg);
    drawLog        (m_ui);

    drawLaunchDialog(m_ui, *m_dbg);
    drawAttachDialog(m_ui, *m_dbg);

    ImGui::Render();
}

void App::buildDefaultDockLayoutIfFirstRun(ImGuiID dockId) {
    if (m_dockLayoutBuilt) return;
    m_dockLayoutBuilt = true;

    // If imgui.ini already has a layout for our windows, respect it.
    if (ImGui::DockBuilderGetNode(dockId) &&
        ImGui::DockBuilderGetNode(dockId)->ChildNodes[0]) {
        return;
    }

    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::DockBuilderRemoveNode(dockId);
    ImGui::DockBuilderAddNode(dockId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockId, vp->WorkSize);

    ImGuiID top   = ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Up,   0.06f, nullptr, &dockId);
    ImGuiID left  = ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Left, 0.55f, nullptr, &dockId);
    ImGuiID right = dockId;

    ImGuiID leftBottom;
    ImGuiID leftTop = ImGui::DockBuilderSplitNode(left, ImGuiDir_Up, 0.60f, nullptr, &leftBottom);

    ImGuiID leftBotRight;
    ImGuiID leftBotLeft = ImGui::DockBuilderSplitNode(leftBottom, ImGuiDir_Left, 0.5f, nullptr, &leftBotRight);

    ImGui::DockBuilderDockWindow("Control",     top);
    ImGui::DockBuilderDockWindow("Disassembly", leftTop);
    ImGui::DockBuilderDockWindow("Registers",   leftBotLeft);
    ImGui::DockBuilderDockWindow("Call Stack",  leftBotRight);
    ImGui::DockBuilderDockWindow("Memory",      right);
    ImGui::DockBuilderDockWindow("Breakpoints", right);
    ImGui::DockBuilderDockWindow("Modules",     right);
    ImGui::DockBuilderDockWindow("Lua",         right);
    ImGui::DockBuilderDockWindow("Log",         right);

    ImGui::DockBuilderFinish(dockId);
}

void App::present() {
    const float clearColor[4]{ 0.08f, 0.08f, 0.09f, 1.0f };
    m_ctx->OMSetRenderTargets(1, &m_rtv, nullptr);
    m_ctx->ClearRenderTargetView(m_rtv, clearColor);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    m_sc->Present(1, 0);
}

void App::shutdown() {
    if (m_dbg) m_dbg->stop();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    dropRenderTarget();
    if (m_sc)  { m_sc->Release();  m_sc  = nullptr; }
    if (m_ctx) { m_ctx->Release(); m_ctx = nullptr; }
    if (m_dev) { m_dev->Release(); m_dev = nullptr; }
    if (m_hwnd) { ::DestroyWindow(m_hwnd); m_hwnd = nullptr; }
    g_app = nullptr;
}

} // namespace mdbg::ui
