// main.cpp — MiniDbg WinMain
#include "common.h"
#include "debugger.h"
#include "ui/app.h"

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    mdbg::Debugger dbg;
    mdbg::ui::App  app;

    if (!app.init(hInst)) {
        ::MessageBoxW(nullptr, L"Failed to initialise UI (D3D11?)",
                       L"MiniDbg", MB_OK | MB_ICONERROR);
        return 1;
    }
    app.bind(&dbg);
    app.run();
    app.shutdown();
    return 0;
}
