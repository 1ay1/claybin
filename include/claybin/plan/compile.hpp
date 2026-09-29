// claybin: policy -> plan.
//
// this is the whole "thinking" step, and it is deliberately pure: it takes a
// sealed policy plus a description of what the host kernel supports, and
// returns a plan and a guarantee report. no syscalls, so every compilation
// decision is unit-testable by describing a fake kernel.
//
// the report is the honest part. if the host cannot enforce something, the
// compiler says `none` instead of quietly dropping it.
#pragma once

#include "claybin/core/error.hpp"
#include "claybin/core/witness.hpp"
#include "claybin/plan/plan.hpp"
#include "claybin/policy/policy.hpp"

namespace clay {

// what the host can actually do. probed once at runtime on linux, but a plain
// value so tests can describe any kernel, including ones that do not exist.
struct HostCapabilities {
    bool user_namespaces{false};
    bool mount_namespaces{false};
    bool pid_namespaces{false};
    bool net_namespaces{false};
    bool uts_namespaces{false};
    bool seccomp{false};
    bool seccomp_user_notif{false};
    bool cgroup_v2{false};
    std::uint32_t landlock_abi{0};  // 0 = absent
    bool no_new_privs{false};

    static HostCapabilities none() { return {}; }

    // a modern linux box. the reference target.
    static HostCapabilities modern_linux() {
        HostCapabilities h;
        h.user_namespaces = h.mount_namespaces = h.pid_namespaces = true;
        h.net_namespaces = h.uts_namespaces = true;
        h.seccomp = h.seccomp_user_notif = true;
        h.cgroup_v2 = true;
        h.landlock_abi = 5;
        h.no_new_privs = true;
        return h;
    }
};

struct Compiled {
    Plan plan;
    GuaranteeReport guarantees;

    // capabilities the policy asked for that the host could not enforce. never
    // silently empty: compile() fails outright when a policy demands strictness
    // the host cannot deliver.
    std::vector<CapId> degraded;

    // assert a floor, and fail if the host did not reach it.
    //
    // this is the difference between api portability and security portability.
    // the same policy compiles on linux, windows and macOS, but the walls you
    // actually get differ. a program that genuinely needs a syscall filter
    // should refuse to run where there is none rather than run unprotected, and
    // this is how it says so:
    //
    //   auto ok = c->require(Enforcement::strong,
    //                        {CapId::fs_read, CapId::syscall_filter});
    //
    // on macOS that fails, because seccomp has no equivalent there.
    Status require(Enforcement floor, std::initializer_list<CapId> caps) const {
        for (CapId id : caps) {
            if (guarantees.strength(id) < floor)
                return std::unexpected(Error{Errc::unsupported, cap_name(id)});
        }
        return {};
    }
};

// compile a sealed policy for a given host.
//
// fails when the policy demands a guarantee the host cannot provide (for
// example Isolation::hardened_process on a kernel with no seccomp). downgrading
// silently would be the single worst thing a sandbox library could do, so it is
// an error the caller has to see.
Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host);

// probe the running kernel. the only impure function in this header; on
// non-linux it reports `none()`.
HostCapabilities probe_host();

}  // namespace clay
