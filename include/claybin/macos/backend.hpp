// claybin: the macOS backend.
//
// it compiles a sealed policy to the primitives macOS actually has:
//
//   seatbelt (SBPL)   the kernel's TrustedBSD MAC policy, reachable from an
//                     unprivileged process via sandbox_init(3). this is the
//                     filesystem and network wall. deprecated in the public
//                     headers since 10.8 and still what Chrome, Safari and
//                     every App Store app run inside today.
//   POSIX rlimits     memory (RLIMIT_AS), pids (RLIMIT_NPROC), cpu time
//                     (RLIMIT_CPU), open files, core size.
//   posix_spawn attrs process group, signal reset, and the exec boundary.
//
// THE HONEST PART, up front, because the whole reason `Enforcement` is not a
// bool is so a backend can say what it cannot do:
//
// 1. there is NO SYSCALL FILTER. seccomp has no macOS equivalent available to
//    an unprivileged process. seatbelt can filter some *operations* by name
//    (`process-fork`, `process-exec`, `sysctl-read`), which is a fixed menu of
//    MAC hooks and not a programmable filter over syscall numbers and argument
//    registers. so SyscallPolicy compiles to the handful of seatbelt operations
//    that happen to correspond, and the report says `partial` at best.
//
// 2. the filesystem model is ACCESS CONTROL, not a tree. seatbelt filters
//    operations on paths; it cannot make /opt/app APPEAR at /app. that is
//    exactly the Fidelity distinction in mounts.hpp, so this backend accepts a
//    Fidelity::exact plan at full strength, accepts `approximate` with the
//    report downgraded, and REFUSES `impossible` rather than silently running
//    a program that can see a path the policy said it could not.
//
// 3. resource limits are rlimits, not cgroups. an rlimit is per-process and
//    inherited, not a shared pool over a tree: four children under a 1 GB
//    RLIMIT_AS can use 4 GB between them. cgroup v2 counts the tree, so this is
//    a genuinely weaker guarantee and reports `partial`, never `strong`.
//    RLIMIT_NPROC is worse still -- it counts processes for the whole UID, not
//    for this tree, so it reports `advisory`.
//
// like the windows backend, compile() is PURE: no sandbox is entered, nothing
// is applied, no syscall is made. that keeps the interesting part -- the
// translation -- testable on any host, which is also how its tests run in CI.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "claybin/core/error.hpp"
#include "claybin/core/witness.hpp"
#include "claybin/policy/policy.hpp"

namespace clay::macos {

// what this host can do. probed the same way as the linux one, and just as
// unwilling to guess: every field defaults to "no".
struct HostCapabilities {
    // sandbox_init(3)/sandbox_init_with_parameters. present since 10.5. the
    // symbols are deprecated-but-exported, and nothing has replaced them for
    // sandboxing an arbitrary binary you did not sign.
    bool seatbelt{false};

    // `(allow file-read* (subpath ...))` style path filters. the SBPL dialect
    // has been stable since 10.7; older dialects spelled subpath differently.
    bool sbpl_path_filters{false};

    // `(deny network*)` with per-endpoint `(remote ip "...")` filters. the
    // coarse deny works everywhere seatbelt does; endpoint filters are the part
    // that is unreliable, so it is a separate bit.
    bool sbpl_network_filters{false};

    // seatbelt operations that correspond to ProcOps: process-fork, process-exec.
    bool sbpl_process_filters{false};

    // POSIX rlimits. always true on a real mac; a bit so tests can describe a
    // host without them.
    bool rlimits{false};

    // Hypervisor.framework -- the only thing on this platform that could honour
    // Isolation::microvm. not used by this backend, reported so compile() can
    // refuse a microvm policy with an accurate reason.
    bool hypervisor{false};

    // darwin major version (24 = macOS 15 Sequoia), for feature gates.
    std::uint32_t darwin_major{0};

    static HostCapabilities none() { return HostCapabilities{}; }

    // a modern mac, for tests. the point of a pure compile step is that this
    // value can describe a machine the test host is not.
    static HostCapabilities modern_macos() {
        HostCapabilities h;
        h.seatbelt = h.sbpl_path_filters = h.sbpl_network_filters = true;
        h.sbpl_process_filters = h.rlimits = h.hypervisor = true;
        h.darwin_major = 24;
        return h;
    }
};

// what this backend is ALLOWED to do, as opposed to what it is able to do.
// defaults are the conservative ones.
struct Options {
    // emit `(deny default)` as the profile's first rule. this is the whole
    // point of the backend and defaulting it off would be absurd; it exists as
    // a knob only so a caller debugging a profile can flip it and watch what
    // the program actually touches with `(allow default)`.
    bool deny_by_default{true};

    // add `(debug deny)` so denials land in the unified log. costs nothing and
    // turns "it exited 1" into a line naming the operation and the path.
    bool trace_denials{false};

    // seatbelt needs a handful of grants no policy ever thinks to ask for --
    // the dyld shared cache, /dev/null, the process's own mach bootstrap port.
    // without them a dynamically linked binary dies before main().
    //
    // this is the macOS analogue of the /lib symlinks in shapes.hpp: not a
    // weakening of the policy so much as the cost of the platform. it is a knob
    // because a caller running a static binary can turn it off, and because an
    // implicit grant that cannot be turned off is one nobody audits.
    bool allow_process_prerequisites{true};

    // name used in the profile comment header, for humans reading a dumped
    // profile or a log line.
    std::string profile_name{};
};

// a compiled macOS sandbox.
//
// the analogue of Plan, but not a byte arena: seatbelt takes a STRING, not a
// syscall stream, and sandbox_init is called before exec in the child rather
// than replayed from a POD. so the "plan" here is the profile text plus the
// handful of numbers that are applied around it.
struct Compiled {
    // ---- seatbelt ----
    // the SBPL profile, ready for sandbox_init_with_parameters(). generated
    // deterministically: same policy in, byte-identical profile out, which is
    // what makes it diffable in a test.
    std::string profile;
    bool use_seatbelt{false};

    // ---- rlimits ----
    // resource, value. applied with setrlimit() in the child between fork and
    // exec. a pair rather than named fields so the list stays open; the
    // resource is the RLIMIT_* constant, which is why it is an int.
    struct Rlimit {
        int resource{0};
        std::uint64_t value{0};

        friend bool operator==(const Rlimit&, const Rlimit&) = default;
    };
    std::vector<Rlimit> rlimits;

    // ---- process ----
    bool new_process_group{false};  // detach from the caller's job control
    bool deny_fork{false};          // (deny process-fork)
    bool deny_exec{false};          // (deny process-exec)

    // ---- network ----
    bool allow_network{false};
    // endpoint allow-list, when the policy named hosts/ports rather than
    // allowing everything. informational when sbpl_network_filters is off.
    std::vector<std::string> network_rules;

    // ---- the audit trail ----
    GuaranteeReport guarantees;
    // capabilities the policy asked for that this host gave us less of than
    // linux would. the caller can print it, refuse to run, or ignore it -- but
    // it cannot say it was not told.
    std::vector<CapId> degraded;
};

// compile for macOS. pure: no sandbox is entered, nothing is applied. that
// keeps it testable on a linux box, which is how this file is developed.
Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host,
                         const Options& opts = {});

// probe the running system. returns none() off macOS.
HostCapabilities probe_host();

// ---------------------------------------------------------------------------
// applying it. the only impure part, and the only part that is macOS-only.
// ---------------------------------------------------------------------------

struct Spawned {
    int pid{-1};
};

// fork, apply the compiled sandbox, exec. mirrors clay::spawn() in
// plan/spawn.hpp, down to the exit codes, so an embedder's supervise loop does
// not need to know which platform it is on.
//
// like its linux sibling this does NOT supervise: no timeout, no output
// pumping, no reaping. that is the loop's job.
//
// `fds` maps CALLER descriptors onto child descriptors (dup2 in the child,
// after the sandbox is entered and before exec), same contract as Command::FdMap.
struct SpawnRequest {
    const char* program{nullptr};
    const char* const* argv{nullptr};
    const char* const* envp{nullptr};

    struct FdMap {
        int parent_fd{-1};
        int child_fd{-1};
    };
    static constexpr int kMaxFdMaps = 8;
    FdMap fds[kMaxFdMaps]{};
    int fd_count{0};

    // -2 means /dev/null, -1 means inherit. same sentinel as Command.
    static constexpr int kDevNull = -2;
    int stdin_fd{-1};
    int stdout_fd{-1};
    int stderr_fd{-1};

    // chdir here in the child, before entering the sandbox. empty = inherit.
    std::string workdir{};
};

// returns in the parent only. on any failure inside the child the child
// _exit()s with kExitPlanFailed/kExitExecFailed rather than returning, because
// a child that survived a failed sandbox setup is UNCONFINED and must not run
// the target program.
Result<Spawned> spawn(const Compiled& compiled, const SpawnRequest& req);

// same exit codes as the linux spawn, deliberately: an embedder that already
// maps 126/127 does not need a macOS branch.
inline constexpr int kExitPlanFailed = 126;
inline constexpr int kExitExecFailed = 127;

}  // namespace clay::macos
