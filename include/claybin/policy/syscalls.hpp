// claybin: syscall authority as a lattice.
//
// a policy is a default action plus a sparse set of per-syscall overrides. the
// actions themselves form a chain ordered by permissiveness, so meet is just
// "the less permissive of the two" applied pointwise. that makes composing two
// syscall profiles automatically safe.
#pragma once

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

#include "claybin/core/lattice.hpp"

namespace clay {

// ordered least-permissive to most-permissive. the numeric order IS the lattice
// order; do not reorder without updating meet().
enum class SysAction : std::uint8_t {
    kill_process = 0,  // SECCOMP_RET_KILL_PROCESS
    kill_thread = 1,
    trap = 2,      // SIGSYS, debuggable
    errno_ = 3,    // fail with an errno, most compatible denial
    notify = 4,    // SECCOMP_RET_USER_NOTIF: delegate to the supervisor
    log = 5,       // allowed, but recorded
    allow = 6,     // SECCOMP_RET_ALLOW
};

constexpr SysAction meet(SysAction a, SysAction b) { return a < b ? a : b; }

constexpr const char* to_string(SysAction a) {
    switch (a) {
        case SysAction::kill_process: return "kill_process";
        case SysAction::kill_thread: return "kill_thread";
        case SysAction::trap: return "trap";
        case SysAction::errno_: return "errno";
        case SysAction::notify: return "notify";
        case SysAction::log: return "log";
        case SysAction::allow: return "allow";
    }
    return "?";
}

using SysNr = std::uint32_t;

struct SyscallRule {
    SysNr nr;
    SysAction action;
    std::uint16_t errno_value;  // only meaningful for SysAction::errno_

    friend bool operator==(const SyscallRule&, const SyscallRule&) = default;
};

class SyscallPolicy {
  public:
    SyscallPolicy() = default;

    static SyscallPolicy nothing() {
        SyscallPolicy p;
        p.default_ = SysAction::kill_process;
        return p;
    }
    static SyscallPolicy everything() {
        SyscallPolicy p;
        p.default_ = SysAction::allow;
        return p;
    }

    SyscallPolicy& set_default(SysAction a, std::uint16_t err = 1 /*EPERM*/) {
        default_ = a;
        default_errno_ = err;
        return *this;
    }

    SyscallPolicy& allow(SysNr nr) { return set(nr, SysAction::allow); }
    SyscallPolicy& allow(std::span<const SysNr> nrs) {
        for (SysNr n : nrs) set(n, SysAction::allow);
        return *this;
    }
    SyscallPolicy& deny(SysNr nr, std::uint16_t err = 1) { return set(nr, SysAction::errno_, err); }
    SyscallPolicy& kill(SysNr nr) { return set(nr, SysAction::kill_process); }
    SyscallPolicy& notify(SysNr nr) { return set(nr, SysAction::notify); }

    SyscallPolicy& set(SysNr nr, SysAction a, std::uint16_t err = 1) {
        for (auto& r : rules_) {
            if (r.nr == nr) {
                r.action = a;
                r.errno_value = err;
                return *this;
            }
        }
        rules_.push_back({nr, a, err});
        std::sort(rules_.begin(), rules_.end(),
                  [](const SyscallRule& x, const SyscallRule& y) { return x.nr < y.nr; });
        return *this;
    }

    SysAction action_for(SysNr nr) const {
        // rules_ is sorted, so this is a binary search in the hot audit path.
        auto it = std::lower_bound(rules_.begin(), rules_.end(), nr,
                                   [](const SyscallRule& r, SysNr v) { return r.nr < v; });
        if (it != rules_.end() && it->nr == nr) return it->action;
        return default_;
    }

    std::uint16_t errno_for(SysNr nr) const {
        auto it = std::lower_bound(rules_.begin(), rules_.end(), nr,
                                   [](const SyscallRule& r, SysNr v) { return r.nr < v; });
        if (it != rules_.end() && it->nr == nr) return it->errno_value;
        return default_errno_;
    }

    SyscallPolicy meet(const SyscallPolicy& o) const {
        SyscallPolicy out;
        out.default_ = clay::meet(default_, o.default_);
        out.default_errno_ = default_errno_;
        // the union of both rule sets is exactly the set of syscalls where the
        // result can differ from the new default.
        auto add = [&](SysNr nr) {
            for (const auto& r : out.rules_)
                if (r.nr == nr) return;
            SysAction a = clay::meet(action_for(nr), o.action_for(nr));
            std::uint16_t e = action_for(nr) <= o.action_for(nr) ? errno_for(nr) : o.errno_for(nr);
            if (a == out.default_) return;  // redundant with the default
            out.rules_.push_back({nr, a, e});
        };
        for (const auto& r : rules_) add(r.nr);
        for (const auto& r : o.rules_) add(r.nr);
        std::sort(out.rules_.begin(), out.rules_.end(),
                  [](const SyscallRule& x, const SyscallRule& y) { return x.nr < y.nr; });
        return out;
    }

    bool subsumes(const SyscallPolicy& o) const {
        if (default_ < o.default_) return false;
        for (const auto& r : rules_)
            if (action_for(r.nr) < o.action_for(r.nr)) return false;
        for (const auto& r : o.rules_)
            if (action_for(r.nr) < o.action_for(r.nr)) return false;
        return true;
    }

    bool is_nothing() const { return default_ == SysAction::kill_process && rules_.empty(); }

    SysAction default_action() const { return default_; }
    std::uint16_t default_errno() const { return default_errno_; }
    const std::vector<SyscallRule>& rules() const { return rules_; }

    friend bool operator==(const SyscallPolicy& a, const SyscallPolicy& b) {
        if (a.default_ != b.default_) return false;
        for (const auto& r : a.rules_)
            if (a.action_for(r.nr) != b.action_for(r.nr)) return false;
        for (const auto& r : b.rules_)
            if (a.action_for(r.nr) != b.action_for(r.nr)) return false;
        return true;
    }

  private:
    SysAction default_{SysAction::kill_process};
    std::uint16_t default_errno_{1};
    std::vector<SyscallRule> rules_;
};

static_assert(Lattice<SyscallPolicy>);

}  // namespace clay
