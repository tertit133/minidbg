#include "theme.h"

#include "imgui.h"

namespace mdbg::ui {

void applyGrayTheme() {
    auto& s = ImGui::GetStyle();
    auto& c = s.Colors;

    s.WindowRounding    = 6.0f;
    s.FrameRounding     = 4.0f;
    s.GrabRounding      = 4.0f;
    s.ScrollbarRounding = 4.0f;
    s.TabRounding       = 4.0f;
    s.WindowBorderSize  = 1.0f;
    s.FrameBorderSize   = 0.0f;
    s.WindowPadding     = ImVec2(10, 10);
    s.FramePadding      = ImVec2(6, 4);
    s.ItemSpacing       = ImVec2(8, 6);
    s.CellPadding       = ImVec2(6, 3);

    const ImVec4 bg      = ImVec4(0.11f, 0.11f, 0.12f, 1.00f);
    const ImVec4 panel   = ImVec4(0.16f, 0.16f, 0.17f, 1.00f);
    const ImVec4 panelHi = ImVec4(0.22f, 0.22f, 0.23f, 1.00f);
    const ImVec4 panelAc = ImVec4(0.30f, 0.30f, 0.32f, 1.00f);
    const ImVec4 border  = ImVec4(0.28f, 0.28f, 0.30f, 1.00f);
    const ImVec4 accent  = ImVec4(0.55f, 0.55f, 0.58f, 1.00f);
    const ImVec4 text    = ImVec4(0.86f, 0.86f, 0.88f, 1.00f);
    const ImVec4 textDim = ImVec4(0.55f, 0.55f, 0.58f, 1.00f);

    c[ImGuiCol_Text]              = text;
    c[ImGuiCol_TextDisabled]      = textDim;
    c[ImGuiCol_WindowBg]          = bg;
    c[ImGuiCol_ChildBg]           = bg;
    c[ImGuiCol_PopupBg]           = panel;
    c[ImGuiCol_Border]            = border;
    c[ImGuiCol_FrameBg]           = panel;
    c[ImGuiCol_FrameBgHovered]    = panelHi;
    c[ImGuiCol_FrameBgActive]     = panelAc;
    c[ImGuiCol_TitleBg]           = panel;
    c[ImGuiCol_TitleBgActive]     = panelHi;
    c[ImGuiCol_TitleBgCollapsed]  = panel;
    c[ImGuiCol_MenuBarBg]         = panel;
    c[ImGuiCol_ScrollbarBg]       = bg;
    c[ImGuiCol_ScrollbarGrab]     = panelHi;
    c[ImGuiCol_ScrollbarGrabHovered] = panelAc;
    c[ImGuiCol_ScrollbarGrabActive]  = accent;
    c[ImGuiCol_CheckMark]         = accent;
    c[ImGuiCol_SliderGrab]        = accent;
    c[ImGuiCol_SliderGrabActive]  = ImVec4(0.70f, 0.70f, 0.72f, 1.00f);
    c[ImGuiCol_Button]            = panel;
    c[ImGuiCol_ButtonHovered]     = panelHi;
    c[ImGuiCol_ButtonActive]      = panelAc;
    c[ImGuiCol_Header]            = panel;
    c[ImGuiCol_HeaderHovered]     = panelHi;
    c[ImGuiCol_HeaderActive]      = panelAc;
    c[ImGuiCol_Separator]         = border;
    c[ImGuiCol_SeparatorHovered]  = accent;
    c[ImGuiCol_SeparatorActive]   = accent;
    c[ImGuiCol_ResizeGrip]        = panel;
    c[ImGuiCol_ResizeGripHovered] = panelHi;
    c[ImGuiCol_ResizeGripActive]  = panelAc;
    c[ImGuiCol_Tab]               = panel;
    c[ImGuiCol_TabHovered]        = panelHi;
    c[ImGuiCol_TabActive]         = panelAc;
    c[ImGuiCol_TabUnfocused]      = panel;
    c[ImGuiCol_TabUnfocusedActive]= panelHi;
    c[ImGuiCol_TableHeaderBg]     = panelHi;
    c[ImGuiCol_TableBorderStrong] = border;
    c[ImGuiCol_TableBorderLight]  = ImVec4(0.22f, 0.22f, 0.23f, 1.00f);
    c[ImGuiCol_TableRowBg]        = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt]     = ImVec4(1, 1, 1, 0.03f);
}

} // namespace mdbg::ui
