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
//
// the result is also masked against handled_access() by the caller: landlock
// rejects a rule whose allowed_access is not a subset of the ruleset's handled
// set, which is a very easy way to turn a working sandbox into a blanket deny.
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
//
// IMPORTANT: we only ever ask for bits we actually know about. landlock keeps
// adding access rights (abi 10 has several we do not model), and asking for a
// bit the kernel does not know makes create_ruleset fail -- but under-asking is
// safe, it just means those operations are unmediated. since our FileRights
// vocabulary tops out at the abi-5 set, that is what we hand over.
std::uint64_t handled_access(std::uint32_t abi) {
    std::uint64_t h = kLlExecute | kLlWriteFile | kLlReadFile | kLlReadDir | kLlRemoveDir |
                      kLlRemoveFile | kLlMakeChar | kLlMakeDir | kLlMakeReg | kLlMakeSock |
                      kLlMakeFifo | kLlMakeBlock | kLlMakeSym;
    if (abi >= 2) h |= kLlRefer;
    if (abi >= 3) h |= kLlTruncate;
    if (abi >= 5) h |= kLlIoctlDev;
    return h;
}

constexpr std::uint64_t kMsRdonly = 1;
constexpr std::uint64_t kMsNosuid = 2;
constexpr std::uint64_t kMsNodev = 4;
constexpr std::uint64_t kMsNoexec = 8;
constexpr std::uint64_t kMsRemount = 32;
constexpr std::uint64_t kMsBind = 4096;
constexpr std::uint64_t kMsRec = 16384;
constexpr std::uint64_t kMsPrivate = 1ull << 18;

// our own flag, well above the kernel's range. marks a mount that may fail
// without failing the sandbox: a device node that does not exist on this host,
// or a --bind-try source. apply() strips it before the syscall.
constexpr std::uint64_t kClayMountOptional = 1ull << 56;

// where the new root is assembled before we pivot into it.
//
// this needs a directory that (a) exists everywhere, (b) we can mount a tmpfs
// over without privilege, and (c) does not SHADOW anything the caller might
// bind from. (c) is the subtle one: staging under /tmp meant that binding a
// source under /tmp -- a perfectly ordinary thing to do -- found the source
// already hidden by our own staging tmpfs, and failed with ENOENT.
//
// /proc/self/fdinfo is the trick bwrap-alikes use: it always exists, it is
// per-process, it is already a virtual filesystem so nothing real is hidden,
// and mounting over it inside our private namespace affects nobody.
constexpr const char* kStageRoot = "/proc/self/fdinfo";
constexpr const char* kOldRoot = "/proc/self/fdinfo/.clay-old";

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

    // -- phase: mounts -----------------------------------------------------
    //
    // this is the bubblewrap model: build a whole new tree out of binds and
    // pivot into it, so the host filesystem is not merely restricted but
    // absent. what is not mounted cannot be named, which is a stronger and much
    // easier-to-audit property than "is denied".
    //
    // a host with no mount namespaces (windows, macOS, a locked-down linux)
    // cannot do this. rather than silently dropping the mounts, we ask the plan
    // how faithfully its OTHER interpretation -- pure access control -- can
    // stand in, and refuse when the answer is "it cannot".
    const bool building_tree = !d.mounts.empty() && host.mount_namespaces;

    if (!d.mounts.empty() && !host.mount_namespaces) {
        std::vector<FidelityNote> notes;
        Fidelity f = d.mounts.fidelity(&notes);
        if (f == Fidelity::impossible) {
            // name the reason. "unsupported" with no explanation is what sends
            // people to strace.
            const char* why = notes.empty() ? "mount plan needs a mount namespace"
                                            : notes.front().reason;
            return std::unexpected(Error{Errc::unsupported, why});
        }
        // approximate: the access interpretation is sound but weaker, so the
        // guarantee report must not claim the tree's strength.
        out.fidelity = f;
    }

    if (building_tree) {
        // 1. make our whole tree private, or every mount we do would propagate
        //    back to the host. bwrap does this first too, and skipping it is a
        //    classic container-escape-by-accident.
        b.op(OpCode::mount, MountOp{b.intern("none"), b.intern("/"), b.intern("none"),
                                    Ref{}, kMsRec | kMsPrivate});

        // 2. a tmpfs to assemble the new root in. mounted directly over the
        //    staging directory, which is a virtual path so nothing real is
        //    hidden and no caller source can be shadowed by it.
        b.op(OpCode::mount, MountOp{b.intern("tmpfs"), b.intern(kStageRoot),
                                    b.intern("tmpfs"), Ref{}, kMsNosuid | kMsNodev});
        // the pivot target has to exist inside the new root
        b.op(OpCode::mkdir_p, MkdirOp{b.intern(kOldRoot), 0755, 0});

        // 3. every requested mount, rebased under the staging root. the source
        //    is interned too, because apply() needs to stat it to decide
        //    whether the mount point should be a file or a directory.
        for (const auto& m : d.mounts.mounts()) {
            std::string dst = std::string(kStageRoot) + path::normalize(m.dest);
            switch (m.kind) {
                case MountKind::bind:
                case MountKind::bind_ro:
                case MountKind::bind_dev: {
                    std::uint64_t flags = kMsBind | kMsRec;
                    if (m.kind != MountKind::bind_dev) flags |= kMsNodev;
                    if (m.kind == MountKind::bind_ro) flags |= kMsRdonly;
                    // nosuid always: a suid binary inside the sandbox is a
                    // privilege path we never want, and no_new_privs alone does
                    // not cover a nested userns.
                    flags |= kMsNosuid;
                    if (m.optional) flags |= kClayMountOptional;
                    // the mount point must exist AND be the same kind of thing
                    // as the source: binding a file onto a directory fails with
                    // ENOTDIR. we cannot stat at compile time (the plan may be
                    // applied on another machine), so emit both and let the
                    // apply step pick -- mkdir_p fails harmlessly if a file is
                    // already there, and touch fails harmlessly if a directory
                    // is. `bind_target` does exactly that.
                    b.op(OpCode::bind_target,
                         BindTargetOp{b.intern(m.source), b.intern(dst)});
                    b.op(OpCode::mount, MountOp{b.intern(m.source), b.intern(dst),
                                                b.intern("none"), Ref{}, flags});
                    // a read-only bind needs a second remount: the kernel
                    // ignores MS_RDONLY on the initial bind, which is a
                    // notorious way to end up with a writable "read-only" mount.
                    // the optional bit has to ride along, or a skipped bind is
                    // followed by a remount of nothing and that fails hard.
                    if (m.kind == MountKind::bind_ro)
                        b.op(OpCode::mount,
                             MountOp{b.intern("none"), b.intern(dst), b.intern("none"), Ref{},
                                     kMsBind | kMsRec | kMsRemount | kMsRdonly | kMsNosuid |
                                         (m.optional ? kClayMountOptional : 0)});
                    break;
                }
                case MountKind::tmpfs: {
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount, MountOp{b.intern("tmpfs"), b.intern(dst),
                                                b.intern("tmpfs"), Ref{},
                                                kMsNosuid | kMsNodev});
                    break;
                }
                case MountKind::proc: {
                    // a fresh procfs shows only our own pid namespace, so the
                    // guest cannot see or signal host processes through /proc.
                    //
                    // NOTE: this requires being a MEMBER of the pid namespace,
                    // not merely its creator. unshare(CLONE_NEWPID) puts our
                    // CHILDREN in the new namespace and leaves us outside it,
                    // so mounting procfs here fails with EPERM. spawn() does a
                    // second fork after apply() for exactly this reason.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount, MountOp{b.intern("proc"), b.intern(dst),
                                                b.intern("proc"), Ref{},
                                                kMsNosuid | kMsNodev | kMsNoexec});
                    break;
                }
                case MountKind::devtmpfs: {
                    // a tmpfs, then bind the handful of device nodes a program
                    // actually needs. binding individual nodes rather than
                    // mounting devtmpfs means /dev/mem and friends are simply
                    // absent rather than present-but-denied.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount, MountOp{b.intern("tmpfs"), b.intern(dst),
                                                b.intern("tmpfs"), Ref{},
                                                kMsNosuid | kMsNoexec});
                    for (const char* node : {"null", "zero", "full", "random", "urandom", "tty"}) {
                        std::string host_node = std::string("/dev/") + node;
                        std::string sand_node = dst + "/" + node;
                        // a bind mount needs the target to EXIST and to be the
                        // same kind of thing, so a device node needs an empty
                        // regular file to land on, not a directory.
                        b.op(OpCode::touch, MkdirOp{b.intern(sand_node), 0600, 0});
                        // optional: /dev/tty does not exist when there is no
                        // controlling terminal, and a missing device node is not
                        // a security failure -- it just is not there. the flag
                        // tells apply() to skip rather than abort.
                        b.op(OpCode::mount,
                             MountOp{b.intern(host_node), b.intern(sand_node), b.intern("none"),
                                     Ref{}, kMsBind | kMsNosuid | kClayMountOptional});
                    }
                    report.record(CapId::device_isolation, Enforcement::strong, "dev allowlist");
                    break;
                }
                case MountKind::symlink: {
                    b.op(OpCode::symlink_at,
                         SymlinkOp{b.intern(m.source), b.intern(dst)});
                    break;
                }
                case MountKind::dir: {
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), m.perms ? m.perms : 0755u, 0});
                    break;
                }
                case MountKind::mqueue:
                    break;
            }
        }

        // 4. pivot into the new tree and detach the old one. after this the
        //    host filesystem is not reachable by any path.
        b.op(OpCode::pivot_root,
             PivotRootOp{b.intern(kStageRoot), b.intern(kOldRoot)});
        b.op(OpCode::umount, UmountOp{b.intern("/.clay-old"), 2 /* MNT_DETACH */});

        report.record(CapId::fs_read, Enforcement::strong, "mount-ns");
        report.record(CapId::fs_write, Enforcement::strong, "mount-ns");
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

    // -- phase: privilege drop (BEFORE landlock) ---------------------------
    // landlock_restrict_self and seccomp both require no_new_privs to already
    // be set, so this phase has to come first. it fails with a bare EPERM
    // otherwise, which is almost impossible to diagnose from the symptom.
    if (host.no_new_privs) {
        b.op(OpCode::no_new_privs, NoNewPrivsOp{0});
        b.op(OpCode::drop_caps, DropCapsOp{0});
        report.record(CapId::privilege_drop, Enforcement::strong, "no_new_privs+bounding-set");
    } else {
        degrade(CapId::privilege_drop);
        // without nnp we cannot install landlock or seccomp at all, so nothing
        // below would work either. say so rather than emitting a plan that is
        // going to fail at apply() time.
        return std::unexpected(
            Error{Errc::unsupported, "no_new_privs required for landlock/seccomp"});
    }

    // -- phase: landlock ---------------------------------------------------
    if (host.landlock_abi > 0) {
        const std::uint64_t handled = handled_access(host.landlock_abi);

        // when a tree was built, landlock rules apply to the SANDBOX paths, not
        // the host ones, because that is what exists after the pivot. the mount
        // plan already describes exactly those, so fold its implied grants in
        // and let meet() keep whichever is tighter.
        FsAuthority effective = d.fs;
        if (!d.mounts.empty()) {
            // the mount plan's other interpretation. on linux this is a second
            // independent wall over the real tree; on a mountless host it is
            // the only wall. same fold either way.
            FsAuthority implied = d.mounts.implied_authority();
            if (building_tree) {
                // the new root itself needs to be listable, or readdir("/")
                // fails and anything that walks the tree looks broken for no
                // visible reason. it is a tmpfs containing only what we
                // mounted, so this grants nothing the caller did not ask for.
                implied.grant("/", FileRights::read());
            }
            // if the caller said nothing about access, the mounts decide it.
            // otherwise intersect: a path must be both mounted AND granted.
            effective = d.fs.is_nothing() ? implied : d.fs.meet(implied);
        }

        for (const auto& g : effective.grants()) {
            // a rule may only allow what the ruleset handles. masking here
            // rather than trusting the translation keeps a future FileRights
            // bit from silently breaking every sandbox.
            std::uint64_t allowed = to_landlock(g.rights, host.landlock_abi) & handled;
            if (allowed == 0) continue;  // a pure deny needs no rule: absence is denial
            b.op(OpCode::landlock_rule, LandlockRuleOp{b.intern(g.path), allowed});
        }
        b.op(OpCode::landlock_enforce,
             LandlockEnforceOp{handled, 0, host.landlock_abi, 0});

        report.record(CapId::fs_read, Enforcement::strong, "landlock");
        report.record(CapId::fs_write, Enforcement::strong, "landlock");
        report.record(CapId::fs_exec, Enforcement::strong, "landlock");
    } else if (!building_tree) {
        degrade(CapId::fs_read);
        degrade(CapId::fs_write);
        degrade(CapId::fs_exec);
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
