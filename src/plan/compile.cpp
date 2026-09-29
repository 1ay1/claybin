#include "claybin/plan/compile.hpp"

#include "claybin/bpf/emit.hpp"

namespace clay {
namespace {

// ---------------------------------------------------------------------------
// linux ABI constants. hardcoded rather than #included so this file compiles
// and tests anywhere; the linux-only apply() step is what actually needs the
// real headers.
// ---------------------------------------------------------------------------

constexpr std::uint64_t kCloneNewns = 0x00020000;
constexpr std::uint64_t kCloneNewuts = 0x04000000;
constexpr std::uint64_t kCloneNewipc = 0x08000000;
constexpr std::uint64_t kCloneNewuser = 0x10000000;
constexpr std::uint64_t kCloneNewpid = 0x20000000;
constexpr std::uint64_t kCloneNewnet = 0x40000000;

// landlock access bits (abi 1-5)
constexpr std::uint64_t kLlExecute = 1ull << 0;
constexpr std::uint64_t kLlWriteFile = 1ull << 1;
constexpr std::uint64_t kLlReadFile = 1ull << 2;
constexpr std::uint64_t kLlReadDir = 1ull << 3;
constexpr std::uint64_t kLlRemoveDir = 1ull << 4;
constexpr std::uint64_t kLlRemoveFile = 1ull << 5;
constexpr std::uint64_t kLlMakeChar = 1ull << 6;
constexpr std::uint64_t kLlMakeDir = 1ull << 7;
constexpr std::uint64_t kLlMakeReg = 1ull << 8;
constexpr std::uint64_t kLlMakeSock = 1ull << 9;
constexpr std::uint64_t kLlMakeFifo = 1ull << 10;
constexpr std::uint64_t kLlMakeBlock = 1ull << 11;
constexpr std::uint64_t kLlMakeSym = 1ull << 12;
constexpr std::uint64_t kLlRefer = 1ull << 13;     // abi 2
constexpr std::uint64_t kLlTruncate = 1ull << 14;  // abi 3
constexpr std::uint64_t kLlIoctlDev = 1ull << 15;  // abi 5

// rlimit resource numbers
constexpr std::uint32_t kRlimitCpu = 0;
constexpr std::uint32_t kRlimitFsize = 1;
constexpr std::uint32_t kRlimitCore = 4;
constexpr std::uint32_t kRlimitNofile = 7;
constexpr std::uint32_t kRlimitAs = 9;
constexpr std::uint32_t kRlimitNproc = 6;

// translate our portable rights to landlock's bits, clamped to what the host's
// abi actually understands. asking for a bit the kernel does not know makes
// landlock_create_ruleset fail outright, so clamping is required, not polite.
std::uint64_t to_landlock(FileRights r, std::uint32_t abi) {
    std::uint64_t out = 0;
    if (r.any(FileRights{FileRights::kExecute})) out |= kLlExecute;
    if (r.any(FileRights{FileRights::kWriteFile})) out |= kLlWriteFile;
    if (r.any(FileRights{FileRights::kReadFile})) out |= kLlReadFile;
    if (r.any(FileRights{FileRights::kReadDir})) out |= kLlReadDir;
    if (r.any(FileRights{FileRights::kRemoveDir})) out |= kLlRemoveDir;
    if (r.any(FileRights{FileRights::kRemoveFile})) out |= kLlRemoveFile;
    if (r.any(FileRights{FileRights::kCreateDir})) out |= kLlMakeDir;
    if (r.any(FileRights{FileRights::kCreateFile})) out |= kLlMakeReg;
    if (r.any(FileRights{FileRights::kMakeSym})) out |= kLlMakeSym;
    if (r.any(FileRights{FileRights::kMakeSpecial}))
        out |= kLlMakeChar | kLlMakeSock | kLlMakeFifo | kLlMakeBlock;
    if (abi >= 2 && r.any(FileRights{FileRights::kRename})) out |= kLlRefer;
    if (abi >= 3 && r.any(FileRights{FileRights::kTruncate})) out |= kLlTruncate;
    if (abi >= 5 && r.any(FileRights{FileRights::kIoctlDev})) out |= kLlIoctlDev;
    return out;
}

// the full set of rights a ruleset governs, for this abi. anything not in here
// is simply not mediated by landlock, so the report must not claim it is.
std::uint64_t handled_access(std::uint32_t abi) {
    std::uint64_t h = kLlExecute | kLlWriteFile | kLlReadFile | kLlReadDir | kLlRemoveDir |
                      kLlRemoveFile | kLlMakeChar | kLlMakeDir | kLlMakeReg | kLlMakeSock |
                      kLlMakeFifo | kLlMakeBlock | kLlMakeSym;
    if (abi >= 2) h |= kLlRefer;
    if (abi >= 3) h |= kLlTruncate;
    if (abi >= 5) h |= kLlIoctlDev;
    return h;
}

}  // namespace

Result<Compiled> compile(const Policy<Sealed>& policy, const HostCapabilities& host) {
    const PolicyData& d = policy.data();
    Compiled out;
    GuaranteeReport::Builder report;
    PlanBuilder b;

    // -- refuse to silently downgrade -------------------------------------
    if (d.isolation == Isolation::microvm)
        return std::unexpected(Error{Errc::unsupported, "microvm backend not implemented"});

    if (d.isolation == Isolation::hardened_process) {
        // hardened means every wall, no exceptions. if the host cannot do one
        // of them, the caller asked for a guarantee we cannot give.
        if (!host.seccomp)
            return std::unexpected(Error{Errc::unsupported, "hardened: seccomp", 0});
        if (host.landlock_abi == 0)
            return std::unexpected(Error{Errc::unsupported, "hardened: landlock", 0});
        if (!host.user_namespaces)
            return std::unexpected(Error{Errc::unsupported, "hardened: user namespaces", 0});
    }

    auto degrade = [&](CapId c) { out.degraded.push_back(c); };

    // -- phase: namespaces -------------------------------------------------
    std::uint64_t unshare_flags = 0;
    if (host.user_namespaces) unshare_flags |= kCloneNewuser;
    if (host.mount_namespaces) unshare_flags |= kCloneNewns;
    if (host.pid_namespaces) unshare_flags |= kCloneNewpid;
    if (host.uts_namespaces) unshare_flags |= kCloneNewuts;
    unshare_flags |= kCloneNewipc;

    // a policy with no network authority gets an empty network namespace, which
    // is a stronger and cheaper guarantee than filtering socket syscalls.
    const bool wants_net = !d.net.is_nothing();
    if (!wants_net && host.net_namespaces) unshare_flags |= kCloneNewnet;

    if (unshare_flags) b.op(OpCode::unshare, UnshareOp{unshare_flags});

    if (host.user_namespaces) {
        // map only our own uid, and deny setgroups first: without that, a
        // process in a new user namespace can drop supplementary groups to
        // bypass a negative group permission.
        b.op(OpCode::write_file,
             WriteFileOp{b.intern("/proc/self/setgroups"), b.intern("deny")});
        b.op(OpCode::write_file, WriteFileOp{b.intern("/proc/self/uid_map"), b.intern("")});
        b.op(OpCode::write_file, WriteFileOp{b.intern("/proc/self/gid_map"), b.intern("")});
        report.record(CapId::proc_isolation, Enforcement::strong, "userns+pidns");
    } else {
        degrade(CapId::proc_isolation);
        report.record(CapId::proc_isolation, Enforcement::none, "unavailable");
    }

    if (!wants_net) {
        if (host.net_namespaces)
            report.record(CapId::net_isolation, Enforcement::strong, "netns");
        else
            degrade(CapId::net_isolation);
    } else {
        // brokered network is only as strong as the notify supervisor, and we
        // have not built it yet. say so.
        report.record(CapId::net_isolation, Enforcement::partial, "policy-only");
    }

    // -- phase: process ----------------------------------------------------
    if (host.uts_namespaces && !d.hostname.empty())
        b.op(OpCode::set_hostname, SetHostnameOp{b.intern(d.hostname)});
    b.op(OpCode::chdir, ChdirOp{b.intern(d.workdir)});

    // rlimits are a coarse backstop and nothing more. RLIMIT_AS caps address
    // space, not resident memory, so a policy that says "512 MB" is not really
    // enforced until the cgroup writes exist. until then the report says
    // `partial` and names rlimit, because claiming cgroup enforcement we never
    // emitted is exactly the lie this report exists to prevent.
    const auto& r = d.resources;
    auto rlimit = [&](std::uint32_t res, std::uint64_t v) {
        b.op(OpCode::set_rlimit, SetRlimitOp{res, 0, v, v});
    };
    if (!r.memory.is_unlimited()) {
        rlimit(kRlimitAs, r.memory.value());
        report.record(CapId::mem_limit, Enforcement::partial, "rlimit-as");
    }
    if (!r.pids.is_unlimited()) {
        rlimit(kRlimitNproc, r.pids.value());
        // RLIMIT_NPROC is per-UID, not per-sandbox: another process running as
        // the same user counts against it. genuinely partial.
        report.record(CapId::pid_limit, Enforcement::partial, "rlimit-nproc");
    }
    if (!r.open_files.is_unlimited()) rlimit(kRlimitNofile, r.open_files.value());
    if (!r.core_size.is_unlimited()) rlimit(kRlimitCore, r.core_size.value());
    if (!r.cpu_time.is_unlimited()) {
        // RLIMIT_CPU is in seconds, and rounding down to 0 would kill instantly.
        std::uint64_t secs = r.cpu_time.value() / 1'000'000'000ull;
        rlimit(kRlimitCpu, secs ? secs : 1);
        report.record(CapId::cpu_limit, Enforcement::partial, "rlimit-cpu");
    }

    // wall-clock is not a kernel mechanism at all: it needs a supervisor with a
    // timer, which is the loop's job. record nothing rather than imply we did.

    // -- phase: landlock ---------------------------------------------------
    if (host.landlock_abi > 0) {
        const auto& grants = d.fs.grants();
        for (const auto& g : grants) {
            std::uint64_t allowed = to_landlock(g.rights, host.landlock_abi);
            if (allowed == 0) continue;  // a pure deny needs no rule: absence is denial
            b.op(OpCode::landlock_rule, LandlockRuleOp{b.intern(g.path), allowed});
        }
        b.op(OpCode::landlock_enforce,
             LandlockEnforceOp{handled_access(host.landlock_abi), 0, host.landlock_abi, 0});

        report.record(CapId::fs_read, Enforcement::strong, "landlock");
        report.record(CapId::fs_write, Enforcement::strong, "landlock");
        report.record(CapId::fs_exec, Enforcement::strong, "landlock");
    } else {
        degrade(CapId::fs_read);
        degrade(CapId::fs_write);
        degrade(CapId::fs_exec);
    }

    // -- phase: privilege drop --------------------------------------------
    // no_new_privs must precede seccomp: the kernel requires it for an
    // unprivileged filter, and without it an suid binary re-grants privilege
    // across exec. the phase ordering in plan.hpp makes this structural.
    if (host.no_new_privs) {
        b.op(OpCode::no_new_privs, NoNewPrivsOp{0});
        b.op(OpCode::drop_caps, DropCapsOp{0});
        report.record(CapId::privilege_drop, Enforcement::strong, "no_new_privs+bounding-set");
    } else {
        degrade(CapId::privilege_drop);
    }

    // -- phase: seccomp (last wall) ---------------------------------------
    if (host.seccomp) {
        SyscallPolicy sys = d.syscalls;
        if (sys.default_action() == SysAction::kill_process && sys.rules().empty()) {
            // a policy that never named a syscall would kill the child before it
            // could exec. that is a policy bug, not something to paper over.
            return std::unexpected(
                Error{Errc::invalid_policy, "seccomp: empty allow-list would kill on exec"});
        }
        auto prog = bpf::compile(sys);
        if (!prog) return std::unexpected(prog.error());

        auto blob = std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(prog->insns.data()),
            prog->insns.size() * sizeof(bpf::Insn)};
        b.op(OpCode::seccomp_install,
             SeccompInstallOp{b.intern_blob(blob), static_cast<std::uint32_t>(prog->insns.size()),
                              0});
        report.record(CapId::syscall_filter, Enforcement::strong, "seccomp-bpf");
    } else {
        degrade(CapId::syscall_filter);
    }

    // the process backend shares a kernel with the host. always say so: this is
    // the single most important line in the whole report.
    report.record(CapId::host_kernel_isolation, Enforcement::none, "process-backend");

    // devices are mediated by the mount namespace's /dev, which we do not build
    // yet. no claim.
    report.record(CapId::device_isolation, Enforcement::none, "no devtmpfs yet");

    auto plan = std::move(b).build();
    if (!plan) return std::unexpected(plan.error());

    out.plan = std::move(*plan);
    out.guarantees = std::move(report).build();
    return out;
}

}  // namespace clay
