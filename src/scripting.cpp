#include "scripting.h"

#include "debugger.h"

#define SOL_ALL_SAFETIES_ON 1
#include <sol/sol.hpp>

#include <mutex>
#include <sstream>

namespace mdbg {

struct Scripting::Impl {
    sol::state               state;
    Debugger*                dbg{};
    std::mutex               outMtx;
    std::mutex               evalMtx;   // serialises UI-thread eval vs. worker-thread evalCondition
    std::vector<std::string> output;

    void pushOutput(std::string s) {
        std::lock_guard<std::mutex> lk(outMtx);
        output.push_back(std::move(s));
    }

    void setupBindings();
};

Scripting::Scripting() : m_impl(std::make_unique<Impl>()) {
    m_impl->state.open_libraries(
        sol::lib::base,
        sol::lib::string,
        sol::lib::math,
        sol::lib::table,
        sol::lib::bit32);
}

Scripting::~Scripting() = default;

void Scripting::bind(Debugger* dbg) {
    m_impl->dbg = dbg;
    m_impl->setupBindings();
}

void Scripting::Impl::setupBindings() {
    // Redirect print() into our output buffer so it shows in the Lua pane.
    state.set_function("print", [this](sol::variadic_args va) {
        std::string line;
        for (auto v : va) {
            if (!line.empty()) line += "\t";
            line += state["tostring"](v).get<std::string>();
        }
        pushOutput(std::move(line));
    });

    auto d = state.create_named_table("dbg");

    d.set_function("log", [this](const std::string& s) {
        pushOutput("[lua] " + s);
    });

    auto toAddr = [](sol::object o) -> Address {
        if (o.is<std::uint64_t>()) return static_cast<Address>(o.as<std::uint64_t>());
        if (o.is<std::int64_t>())  return static_cast<Address>(o.as<std::int64_t>());
        if (o.is<double>())        return static_cast<Address>(o.as<double>());
        return 0;
    };

    d.set_function("readU8", [this, toAddr](sol::object a) -> std::uint8_t {
        if (!dbg) return 0;
        std::uint8_t v = 0;
        dbg->readMemory(toAddr(a), &v, sizeof(v));
        return v;
    });
    d.set_function("readU16", [this, toAddr](sol::object a) -> std::uint16_t {
        if (!dbg) return 0;
        std::uint16_t v = 0;
        dbg->readMemory(toAddr(a), &v, sizeof(v));
        return v;
    });
    d.set_function("readU32", [this, toAddr](sol::object a) -> std::uint32_t {
        if (!dbg) return 0;
        std::uint32_t v = 0;
        dbg->readMemory(toAddr(a), &v, sizeof(v));
        return v;
    });
    d.set_function("readU64", [this, toAddr](sol::object a) -> std::uint64_t {
        if (!dbg) return 0;
        std::uint64_t v = 0;
        dbg->readMemory(toAddr(a), &v, sizeof(v));
        return v;
    });
    d.set_function("readPtr", [this, toAddr](sol::object a) -> std::uint64_t {
        if (!dbg) return 0;
        std::uint64_t v = 0;
        dbg->readMemory(toAddr(a), &v, sizeof(v));
        return v;
    });

    d.set_function("writeU8", [this, toAddr](sol::object a, std::uint8_t v) {
        if (dbg) dbg->writeMemory(toAddr(a), &v, sizeof(v));
    });
    d.set_function("writeU16", [this, toAddr](sol::object a, std::uint16_t v) {
        if (dbg) dbg->writeMemory(toAddr(a), &v, sizeof(v));
    });
    d.set_function("writeU32", [this, toAddr](sol::object a, std::uint32_t v) {
        if (dbg) dbg->writeMemory(toAddr(a), &v, sizeof(v));
    });
    d.set_function("writeU64", [this, toAddr](sol::object a, std::uint64_t v) {
        if (dbg) dbg->writeMemory(toAddr(a), &v, sizeof(v));
    });

    d.set_function("readBytes",
        [this, toAddr](sol::object a, int n) -> sol::table {
            sol::table t = state.create_table();
            if (!dbg || n <= 0) return t;
            std::vector<std::uint8_t> buf(static_cast<size_t>(n));
            dbg->readMemory(toAddr(a), buf.data(), buf.size());
            for (int i = 0; i < n; ++i) t[i + 1] = buf[i];
            return t;
        });

    // Snapshot-based register access. We re-fetch per call so scripts see
    // current values even across pauses in a loop.
    d.set_function("rip",       [this]{ return dbg ? dbg->snapshot().ctx.Rip    : 0ull; });
    d.set_function("rax",       [this]{ return dbg ? dbg->snapshot().ctx.Rax    : 0ull; });
    d.set_function("rbx",       [this]{ return dbg ? dbg->snapshot().ctx.Rbx    : 0ull; });
    d.set_function("rcx",       [this]{ return dbg ? dbg->snapshot().ctx.Rcx    : 0ull; });
    d.set_function("rdx",       [this]{ return dbg ? dbg->snapshot().ctx.Rdx    : 0ull; });
    d.set_function("rsi",       [this]{ return dbg ? dbg->snapshot().ctx.Rsi    : 0ull; });
    d.set_function("rdi",       [this]{ return dbg ? dbg->snapshot().ctx.Rdi    : 0ull; });
    d.set_function("rsp",       [this]{ return dbg ? dbg->snapshot().ctx.Rsp    : 0ull; });
    d.set_function("rbp",       [this]{ return dbg ? dbg->snapshot().ctx.Rbp    : 0ull; });
    d.set_function("imageBase", [this]{ return dbg ? dbg->snapshot().pid        : 0ull; });
    // (imageBase isn't in Snapshot; we expose pid here. TODO: extend snapshot.)

    d.set_function("addBp", [this, toAddr](sol::object a) -> std::uint32_t {
        if (!dbg) return 0;
        return dbg->addBreakpoint(toAddr(a));
    });
    d.set_function("rmBp", [this](std::uint32_t id) -> bool {
        if (!dbg) return false;
        return dbg->removeBreakpoint(id);
    });
    d.set_function("continueExec", [this]{ if (dbg) dbg->run(); });
    d.set_function("stepInto",     [this]{ if (dbg) dbg->stepInto(); });
    d.set_function("stepOver",     [this]{ if (dbg) dbg->stepOver(); });
}

std::string Scripting::eval(const std::string& code) {
    std::lock_guard<std::mutex> lk(m_impl->evalMtx);
    try {
        auto r = m_impl->state.safe_script(code, sol::script_pass_on_error);
        if (!r.valid()) {
            sol::error err = r;
            return std::string("error: ") + err.what();
        }
        return "ok";
    } catch (const sol::error& e) {
        return std::string("error: ") + e.what();
    } catch (const std::exception& e) {
        return std::string("exception: ") + e.what();
    }
}

bool Scripting::evalCondition(const std::string& code) {
    std::lock_guard<std::mutex> lk(m_impl->evalMtx);
    try {
        // Try as an expression first — lets users write "dbg.rax() == 42"
        // without the `return` prefix. If that parses and runs, use its
        // value. Otherwise fall through to executing it as a block.
        std::string wrapped = "return (" + code + ")";
        auto r = m_impl->state.safe_script(wrapped, sol::script_pass_on_error);
        if (r.valid()) {
            sol::object v = r;
            if (v.is<bool>())        return v.as<bool>();
            if (v.is<sol::nil_t>())  return true;  // nil = pause
            // Any non-nil Lua value is truthy.
            return true;
        }

        // Fall back: run as a block, look at its returned value.
        r = m_impl->state.safe_script(code, sol::script_pass_on_error);
        if (!r.valid()) {
            // Surface the error so the user can fix it.
            sol::error err = r;
            m_impl->pushOutput(std::string("[bp-script error] ") + err.what());
            return true;
        }
        if (r.return_count() == 0) return true;
        sol::object v = r;
        if (v.is<bool>()) return v.as<bool>();
        return true;
    } catch (const std::exception& e) {
        m_impl->pushOutput(std::string("[bp-script exception] ") + e.what());
        return true;
    }
}

std::vector<std::string> Scripting::drainOutput() {
    std::lock_guard<std::mutex> lk(m_impl->outMtx);
    auto v = std::move(m_impl->output);
    m_impl->output.clear();
    return v;
}

} // namespace mdbg
