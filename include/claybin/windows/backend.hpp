// claybin: the windows backend.
//
// this file exists to prove the IR was designed right, and to be honest about
// where it is not. it compiles a sealed policy to windows primitives:
//
//   AppContainer         a capability SID; the process runs with a token that
//                        has no access to anything not granted to that SID
//   restricted token     drops groups and privileges from the token
//   Job Object           memory, cpu and process-count limits. genuinely the
//                        equal of cgroup v2 here, sometimes better.
//   mitigation policies  a fixed menu (no dynamic code, no child processes,
//                        signature requirements), NOT arbitrary syscall filtering
//
// THE HONEST PART, up front. windows differs from linux in two ways that no
// amount of API design hides:
//
// 1. there is no syscall filter. seccomp has no windows equivalent available to
//    a normal process. Process Mitigation Policies are a menu of hardening
//    switches, not a programmable filter. so SyscallPolicy compiles to a subset
//    of those switches and the report says `partial` at best, `none` usually.
//
// 2. the filesystem model is ACL-on-object, not path-prefix. linux landlock
//    says "this subtree, these rights" in one call. windows says "this object's
//    DACL grants this SID these rights", per object. so a recursive grant means
//    walking the tree and stamping ACEs, which (a) is slow, (b) MUTATES THE HOST
//    FILESYSTEM, and (c) needs cleaning up afterwards.
//
// (b) is the important one. claybin's whole premise is that a policy is a
// description with no side effects until it is applied to a child. on windows a
// filesystem grant has a side effect on the host, so this backend refuses to do
// it implicitly: the caller must opt in with `allow_host_acl_mutation`, and if
// they do not, filesystem grants report `partial` (enforced by the AppContainer's
// default deny, not by our grants) rather than `strong`.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "claybin/core/error.hpp"
#include "claybin/core/witness.hpp"
#include "claybin/policy/policy.hpp"

namespace clay::windows {

// what this host can do. the windows analogue of HostCapabilities, probed the
// same way and just as unwilling to guess.
struct HostCapabilities {
    bool app_container{false};     // win8+; the main sandbox primitive
    bool job_objects{false};       // nt-era, always present in practice
    bool nested_jobs{false};       // win8+; without it a job inside a job fails
    bool mitigation_policies{false};  // win8+
    bool restricted_tokens{false};
    bool wfp{false};               // windows filtering platform, for network
    bool lowbox_network{false};    // appcontainer network capability control
    std::uint32_t build{0};        // major build number, for feature gates

    static HostCapabilities none() { return {}; }

    static HostCapabilities modern_windows() {
        HostCapabilities h;
        h.app_container = h.job_objects = h.nested_jobs = true;
        h.mitigation_policies = h.restricted_tokens = true;
        h.wfp = h.lowbox_network = true;
        h.build = 22000;
        return h;
    }
};

// the options that change what this backend is ALLOWED to do, as opposed to
// what it is able to do. defaults are the conservative ones.
struct Options {
    // permit stamping ACEs onto host filesystem objects to implement grants.
    // off by default: it mutates state outside the sandbox, which every other
    // claybin backend never does. with it off, filesystem enforcement comes
    // only from the AppContainer's default-deny and reports `partial`.
    bool allow_host_acl_mutation{false};

    // an AppContainer profile name. a stable name means a stable capability SID,
    // so grants persist across runs -- convenient, but it also means two
    // sandboxes sharing a name share authority. unnamed (the default) derives a
    // fresh one per sandbox.
    std::string profile_name{};
};

// a compiled windows sandbox. the analogue of Plan, but not a byte arena: the
// win32 API takes structs and handles, not a syscall stream, so there is nothing
// to serialize and no fork to survive.
struct Compiled {
    // ---- appcontainer ----
    bool use_app_container{false};
    std::string container_name;
    // capability SIDs to grant, as strings. deliberately a small set: each one
    // is a broad grant, so they are listed rather than computed.
    std::vector<std::string> capabilities;

    // ---- job object limits ----
    std::uint64_t memory_limit_bytes{0};   // 0 = none
    std::uint32_t active_process_limit{0}; // 0 = none
    std::uint64_t cpu_rate_percent{0};     // 0 = none; job object CPU rate control
    std::uint64_t user_time_limit_100ns{0};

    // ---- mitigation policies ----
    bool disable_dynamic_code{false};
    bool disable_child_processes{false};
    bool disable_win32k{false};          // no gdi/user32 syscalls
    bool block_non_microsoft_binaries{false};
    bool disable_extension_points{false};

    // ---- filesystem ----
    // paths the sandbox may read/write, already resolved. only meaningful when
    // Options::allow_host_acl_mutation is set; otherwise informational, and the
    // report says so.
    std::vector<std::pair<std::string, std::uint32_t>> acl_grants;
    bool acls_applied{false};

    // ---- network ----
    bool allow_network{false};

    GuaranteeReport guarantees;
    std::vector<CapId> degraded;
};

// compile for windows. pure: no handles are created, nothing is applied. that
// keeps it testable on a linux box, which is how this file is developed and how
// its tests run in CI.
Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host,
                         const Options& opts = {});

// probe the running system. returns none() off windows.
HostCapabilities probe_host();

}  // namespace clay::windows
