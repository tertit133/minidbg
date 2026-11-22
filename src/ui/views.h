// views.h — individual debugger panes
#pragma once

#include "app.h"

namespace mdbg::ui {

void drawControlBar  (UiState& ui, Debugger& dbg, const DebuggerSnapshot& snap);
void drawDisasm      (UiState& ui, Debugger& dbg, const DebuggerSnapshot& snap);
void drawRegisters   (const DebuggerSnapshot& snap);
void drawCallStack   (UiState& ui, Debugger& dbg, const DebuggerSnapshot& snap);
void drawMemory      (UiState& ui, Debugger& dbg);
void drawBreakpoints (UiState& ui, Debugger& dbg);
void drawModules     (UiState& ui, Debugger& dbg);
void drawLua         (UiState& ui, Debugger& dbg);
void drawLog         (UiState& ui);

void drawLaunchDialog(UiState& ui, Debugger& dbg);
void drawAttachDialog(UiState& ui, Debugger& dbg);

} // namespace mdbg::ui
