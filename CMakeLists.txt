cmake_minimum_required(VERSION 3.20)
project(minidbg LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "MiniDbg is Windows-only (uses the Win32 Debug API).")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:preprocessor /EHsc /utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

include(FetchContent)

# ---- Zydis (disassembler) --------------------------------------------------
set(ZYDIS_BUILD_TOOLS   OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.0
)
FetchContent_MakeAvailable(zydis)

# ---- Dear ImGui (no official CMake — pull sources and compile locally) -----
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.90.5-docking
)
FetchContent_MakeAvailable(imgui)

# ---- Lua 5.4 (vendored static library) -------------------------------------
# The upstream Lua repo ships no CMakeLists, so we glob *.c and compile.
FetchContent_Declare(
    lua_src
    GIT_REPOSITORY https://github.com/lua/lua.git
    GIT_TAG        v5.4.6
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(lua_src)
if(NOT lua_src_POPULATED)
    FetchContent_Populate(lua_src)
endif()

file(GLOB LUA_CSRC ${lua_src_SOURCE_DIR}/*.c)
list(FILTER LUA_CSRC EXCLUDE REGEX "(lua\\.c|luac\\.c|onelua\\.c)$")
add_library(lua_vendored STATIC ${LUA_CSRC})
set_target_properties(lua_vendored PROPERTIES LINKER_LANGUAGE C)
target_include_directories(lua_vendored PUBLIC ${lua_src_SOURCE_DIR})
if(MSVC)
    target_compile_definitions(lua_vendored PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(lua_vendored PRIVATE /w)
endif()

# ---- sol2 (header-only C++ Lua wrapper) ------------------------------------
FetchContent_Declare(
    sol2
    GIT_REPOSITORY https://github.com/ThePhD/sol2.git
    GIT_TAG        v3.3.0
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(sol2)
if(NOT sol2_POPULATED)
    FetchContent_Populate(sol2)
endif()
add_library(sol2_hdr INTERFACE)
target_include_directories(sol2_hdr INTERFACE ${sol2_SOURCE_DIR}/include)
target_link_libraries(sol2_hdr INTERFACE lua_vendored)
target_compile_features(sol2_hdr INTERFACE cxx_std_17)

set(IMGUI_SOURCES
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)

# ---- minidbg executable ----------------------------------------------------
add_executable(minidbg WIN32
    src/main.cpp
    src/process.cpp
    src/disasm.cpp
    src/breakpoint.cpp
    src/hwbreakpoint.cpp
    src/context.cpp
    src/symbols.cpp
    src/pe.cpp
    src/scripting.cpp
    src/debugger.cpp
    src/ui/theme.cpp
    src/ui/app.cpp
    src/ui/views.cpp
    ${IMGUI_SOURCES}
)

target_include_directories(minidbg PRIVATE
    src
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

target_link_libraries(minidbg PRIVATE
    Zydis
    sol2_hdr
    d3d11 dxgi dxguid dwmapi psapi dbghelp
)

set_target_properties(minidbg PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
