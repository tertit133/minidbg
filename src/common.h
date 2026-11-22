// common.h — shared types, Windows includes, utility helpers
#pragma once

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace mdbg {

using Address = std::uintptr_t;
using Byte    = std::uint8_t;
using Bytes   = std::vector<Byte>;

enum class DebuggerState {
    Idle,       // nothing attached
    Running,    // debuggee executing
    Paused,     // debuggee stopped (bp / exception / step)
    Exited,     // debuggee gone, worker finished
};

// Events the engine pushes up to the UI (via drainEvents()).
struct DebugEvent {
    enum class Kind {
        ProcessCreated,
        ProcessExited,
        ThreadCreated,
        ThreadExited,
        DllLoaded,
        DllUnloaded,
        BreakpointHit,
        SingleStep,
        Exception,
        OutputDebugString,
    } kind{};
    DWORD   pid{};
    DWORD   tid{};
    Address address{};
    DWORD   exceptionCode{};
    std::string text;
};

// ----- UTF-8 / wide string helpers ------------------------------------------
inline std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

inline std::string wide_to_utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(),
                                   nullptr, 0, nullptr, nullptr);
    std::string u(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(),
                           u.data(), n, nullptr, nullptr);
    return u;
}

// printf-style formatter → std::string, bounded buffer.
template <typename... Args>
inline std::string sfmt(const char* fmt, Args... args) {
    char buf[512];
    int n = std::snprintf(buf, sizeof(buf), fmt, args...);
    if (n < 0) return {};
    return std::string(buf, static_cast<size_t>(std::min<int>(n, sizeof(buf) - 1)));
}

} // namespace mdbg
