#include "claybin/plan/compile.hpp"

#include <cstdio>
#include <unistd.h>

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
constexpr std::uint64_t kMsSlave = 1ull << 19;
constexpr std::uint64_t kMsSilent = 1ull << 15;

// our own flag, well above the kernel's range. marks a mount that may fail
// without failing the sandbox: a device node that does not exist on this host,
// or a --bind-try source. apply() strips it before the syscall.
constexpr std::uint64_t kClayMountOptional = 1ull << 56;

// where the new root is assembled before we pivot into it.
//
// bubblewrap's layout, and for its reasons: a base tmpfs with a "newroot"
// subdirectory inside it. pivoting to the SUBDIRECTORY rather than the base
// means a caller who binds something over / (or over the base path itself)
// cannot break our access to the old root mid-setup.
constexpr const char* kStageBase = "/tmp/.clay";
constexpr const char* kNewRoot = "/tmp/.clay/newroot";
constexpr const char* kOldRoot = "/tmp/.clay/oldroot";

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

        // an empty content ref means "map my own id to itself", computed at
        // apply time because the plan may be built by another process. an
        // explicit --uid/--gid writes the mapping here instead.
        //
        // note an unprivileged user namespace can only map ONE id, and only one
        // it already owns, so `--uid 0` maps our real uid to 0 inside. that is
        // what bwrap does too, and it is not a privilege gain: uid 0 in a user
        // namespace owns nothing outside it.
        if (d.uid != kUnsetId) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "%u %u 1\n", d.uid,
                          static_cast<unsigned>(::getuid()));
            b.op(OpCode::write_file,
                 WriteFileOp{b.intern("/proc/self/uid_map"), b.intern(buf)});
        } else {
            b.op(OpCode::write_file, WriteFileOp{b.intern("/proc/self/uid_map"), b.intern("")});
        }
        if (d.gid != kUnsetId) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "%u %u 1\n", d.gid,
                          static_cast<unsigned>(::getgid()));
            b.op(OpCode::write_file,
                 WriteFileOp{b.intern("/proc/self/gid_map"), b.intern(buf)});
        } else {
            b.op(OpCode::write_file, WriteFileOp{b.intern("/proc/self/gid_map"), b.intern("")});
        }
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
        // counts tmp_overlay scratch areas, so each gets its own tmpfs rather
        // than sharing one and leaking changes between overlays.
        std::size_t ovl_index = 0;

        // 1. mark everything SLAVE, not private.
        //
        //    slave means we still RECEIVE mounts from the host but never
        //    propagate ours back to it. private would cut both directions,
        //    which sounds tighter but is actually worse: a long-running sandbox
        //    would silently miss a later host mount under a path it has bound,
        //    and see a stale tree. this is what bubblewrap does and the reason
        //    is worth copying along with the flag.
        b.op(OpCode::mount, MountOp{b.intern("none"), b.intern("/"), b.intern("none"),
                                    Ref{}, kMsRec | kMsSlave | kMsSilent});

        // 2. a tmpfs for the staging area, then newroot/ and oldroot/ inside it.
        //    pivoting to the SUBDIRECTORY (not the tmpfs root) is deliberate: a
        //    caller who binds something over / or over the staging path cannot
        //    then break our own access to the old root.
        b.op(OpCode::mkdir_p, MkdirOp{b.intern(kStageBase), 0755, 0});
        b.op(OpCode::mount, MountOp{b.intern("tmpfs"), b.intern(kStageBase),
                                    b.intern("tmpfs"), Ref{}, kMsNosuid | kMsNodev});
        b.op(OpCode::mkdir_p, MkdirOp{b.intern(kNewRoot), 0755, 0});
        // newroot must itself be a MOUNT POINT for the second pivot_root to
        // work -- pivot_root(".", ".") returns EINVAL on a plain directory. a
        // recursive bind of the directory onto itself is how bubblewrap does
        // it, and it costs nothing.
        b.op(OpCode::mount, MountOp{b.intern(kNewRoot), b.intern(kNewRoot), b.intern("none"),
                                    Ref{}, kMsBind | kMsRec | kMsSilent});
        b.op(OpCode::mkdir_p, MkdirOp{b.intern(kOldRoot), 0755, 0});

        // 3. every requested mount, rebased under the NEW ROOT. the source
        //    is interned too, because apply() needs to stat it to decide
        //    whether the mount point should be a file or a directory.
        for (const auto& m : d.mounts.mounts()) {
            std::string dst = std::string(kNewRoot) + path::normalize(m.dest);
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
                    // a bind mount DOES NOT APPLY ITS FLAGS -- the kernel
                    // ignores MS_RDONLY and friends on the initial bind -- and a
                    // plain remount only affects the top mount. so every bind
                    // gets a recursive remount that walks mountinfo and ORs the
                    // flags onto each submount's existing ones.
                    //
                    // without this, `--ro-bind /home /home` on a machine where
                    // /home/x is its own mount leaves /home/x writable. that is
                    // a silent hole, and it is why this op exists rather than
                    // the single remount that was here before.
                    std::uint64_t add = kMsNosuid;
                    if (m.kind != MountKind::bind_dev) add |= kMsNodev;
                    if (m.kind == MountKind::bind_ro) add |= kMsRdonly;
                    b.op(OpCode::remount_recursive,
                         RemountRecursiveOp{b.intern(dst),
                                            add | (m.optional ? kClayMountOptional : 0)});
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
                    //
                    // the node list and the layout follow bubblewrap exactly,
                    // because guests depend on the details: six real devices
                    // bound in, then stdin/stdout/stderr as SYMLINKS into
                    // /proc/self/fd (they are not devices and cannot be bound),
                    // then a devpts instance with a ptmx symlink so a guest can
                    // actually allocate a pty.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount, MountOp{b.intern("tmpfs"), b.intern(dst),
                                                b.intern("tmpfs"), Ref{},
                                                kMsNosuid | kMsNoexec});
                    for (const char* node : {"null", "zero", "full", "random", "urandom",
                                             "tty"}) {
                        std::string host_node = std::string("/dev/") + node;
                        std::string sand_node = dst + "/" + node;
                        // a bind mount needs the target to EXIST and to be the
                        // same kind of thing, so a device node needs an empty
                        // regular file to land on, not a directory.
                        b.op(OpCode::touch, MkdirOp{b.intern(sand_node), 0444, 0});
                        // optional: /dev/tty does not exist when there is no
                        // controlling terminal, and a missing device node is not
                        // a security failure -- it just is not there.
                        b.op(OpCode::mount,
                             MountOp{b.intern(host_node), b.intern(sand_node), b.intern("none"),
                                     Ref{}, kMsBind | kClayMountOptional});
                    }
                    // stdio are symlinks into procfs, not devices.
                    for (int fdno = 0; fdno < 3; ++fdno) {
                        static const char* names[] = {"stdin", "stdout", "stderr"};
                        std::string target = "/proc/self/fd/" + std::to_string(fdno);
                        b.op(OpCode::symlink_at,
                             SymlinkOp{b.intern(target), b.intern(dst + "/" + names[fdno])});
                    }
                    // and so are these two: /dev/fd is the classic alias for a
                    // process's own descriptor table, /dev/core for its memory.
                    b.op(OpCode::symlink_at,
                         SymlinkOp{b.intern("/proc/self/fd"), b.intern(dst + "/fd")});
                    b.op(OpCode::symlink_at,
                         SymlinkOp{b.intern("/proc/kcore"), b.intern(dst + "/core")});
                    // a private devpts, so a guest can open a pty without
                    // reaching the host's. newinstance is what keeps it private.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst + "/pts"), 0755, 0});
                    b.op(OpCode::mount,
                         MountOp{b.intern("devpts"), b.intern(dst + "/pts"), b.intern("devpts"),
                                 b.intern("newinstance,ptmxmode=0666,mode=620"),
                                 kMsNosuid | kMsNoexec | kClayMountOptional});
                    b.op(OpCode::symlink_at,
                         SymlinkOp{b.intern("pts/ptmx"), b.intern(dst + "/ptmx")});
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst + "/shm"), 0755, 0});

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
                case MountKind::mqueue: {
                    // a posix message queue filesystem, its own instance, so the
                    // guest cannot see or write host queues.
                    //
                    // NOT optional: mounting mqueue needs privilege an
                    // unprivileged user namespace does not have, so this usually
                    // fails -- and bubblewrap fails too. making it optional would
                    // mean claybin "succeeds" with no /dev/mqueue while the caller
                    // believes they got one, which is exactly the kind of quiet
                    // divergence this library exists to avoid.
                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount,
                         MountOp{b.intern("mqueue"), b.intern(dst), b.intern("mqueue"), Ref{},
                                 kMsNosuid | kMsNodev | kMsNoexec});
                    break;
                }

                case MountKind::file:
                case MountKind::bind_data:
                case MountKind::bind_data_ro: {
                    // copy the caller's fd into the tree. the fd number travels
                    // in the op, and the copy happens post-fork where we are
                    // already inside the namespace -- so the bytes land on OUR
                    // tmpfs and never touch a host path.
                    std::uint32_t flags = 0;
                    if (m.kind != MountKind::file) flags |= 1;  // bind it in
                    if (m.kind == MountKind::bind_data_ro) flags |= 2;  // read-only
                    b.op(OpCode::write_fd_content,
                         WriteFdContentOp{b.intern(dst),
                                          static_cast<std::int32_t>(m.content_fd),
                                          m.perms ? m.perms : 0644u, flags});
                    break;
                }

                case MountKind::overlay:
                case MountKind::tmp_overlay:
                case MountKind::ro_overlay: {
                    // overlayfs takes its layers as a comma-separated option
                    // string, so a layer path containing a comma or a colon has
                    // to be escaped or the kernel parses it as a separator and
                    // silently mounts the wrong thing.
                    auto esc = [](const std::string& p) {
                        std::string o;
                        for (char c : p) {
                            if (c == ',' || c == ':' || c == '\\') o.push_back('\\');
                            o.push_back(c);
                        }
                        return o;
                    };

                    std::string opts = "lowerdir=";
                    bool first = true;
                    for (const auto& l : m.lowers) {
                        if (!first) opts += ":";
                        first = false;
                        opts += esc(l);
                    }

                    if (m.kind == MountKind::overlay) {
                        opts += ",upperdir=" + esc(m.source);
                        opts += ",workdir=" + esc(m.workdir);
                    } else if (m.kind == MountKind::tmp_overlay) {
                        // the upper and work layers live on a tmpfs we mount
                        // ourselves, so every change the guest makes is
                        // discarded when the sandbox exits. the tmpfs has to be
                        // mounted BEFORE the overlay that uses it.
                        std::string scratch = std::string(kStageBase) + "/ovl" +
                                              std::to_string(ovl_index);
                        b.op(OpCode::mkdir_p, MkdirOp{b.intern(scratch), 0755, 0});
                        b.op(OpCode::mount,
                             MountOp{b.intern("tmpfs"), b.intern(scratch), b.intern("tmpfs"),
                                     Ref{}, kMsNosuid | kMsNodev});
                        b.op(OpCode::mkdir_p, MkdirOp{b.intern(scratch + "/upper"), 0755, 0});
                        b.op(OpCode::mkdir_p, MkdirOp{b.intern(scratch + "/work"), 0755, 0});
                        opts += ",upperdir=" + esc(scratch + "/upper");
                        opts += ",workdir=" + esc(scratch + "/work");
                        ++ovl_index;
                    }
                    // ro_overlay gets no upperdir at all, which is what makes
                    // the merged view unwritable.

                    // userxattr is REQUIRED in a user namespace: without it the
                    // kernel tries to use trusted.* xattrs, which need
                    // CAP_SYS_ADMIN in the init namespace, and the mount fails
                    // with EPERM for no visible reason.
                    opts += ",userxattr";

                    b.op(OpCode::mkdir_p, MkdirOp{b.intern(dst), 0755, 0});
                    b.op(OpCode::mount,
                         MountOp{b.intern("overlay"), b.intern(dst), b.intern("overlay"),
                                 b.intern(opts), kMsNosuid | kMsNodev});
                    break;
                }
            }
        }

        // 4. pivot into the new tree and detach the old one.
        //
        //    two pivots, following bubblewrap. the first moves us into the
        //    staging tmpfs with the real root parked at oldroot/. the second
        //    uses the pivot_root(".", ".") trick: put_old is allowed to be the
        //    same directory as new_root, which stacks the old root ON TOP of
        //    itself and lets us umount it with no leftover directory in the
        //    guest's tree. doing it the obvious way leaves a visible /oldroot
        //    that the guest can see even after the detach.
        b.op(OpCode::pivot_root, PivotRootOp{b.intern(kStageBase), b.intern("oldroot")});
        b.op(OpCode::pivot_into_newroot, PivotRootOp{b.intern("/newroot"), Ref{}});

        report.record(CapId::fs_read, Enforcement::strong, "mount-ns");
        report.record(CapId::fs_write, Enforcement::strong, "mount-ns");
    }

    // -- phase: process ----------------------------------------------------
    if (host.uts_namespaces && !d.hostname.empty())
        b.op(OpCode::set_hostname, SetHostnameOp{b.intern(d.hostname)});

    // a new session detaches the guest from the host's controlling terminal.
    // that is not cosmetic: a guest sharing a tty can inject keystrokes into it
    // with TIOCSTI, which is a genuine escape when the host side is a shell.
    if (d.new_session) b.op(OpCode::new_session, NoNewPrivsOp{0});

    // and this makes an orphaned sandbox die rather than linger unsupervised.
    if (d.die_with_parent) b.op(OpCode::die_with_parent, NoNewPrivsOp{0});

    // an explicit --uid/--gid means the guest should RUN as that id, not merely
    // have it mapped. the mapping was written in the namespace phase; this is
    // the setresuid/setresgid that actually adopts it.
    if (d.uid != kUnsetId || d.gid != kUnsetId) {
        b.op(OpCode::set_ids,
             SetIdsOp{d.uid == kUnsetId ? static_cast<std::uint32_t>(::getuid()) : d.uid,
                      d.gid == kUnsetId ? static_cast<std::uint32_t>(::getgid()) : d.gid});
    }

    b.op(OpCode::chdir, ChdirOp{b.intern(d.workdir)});

    // rlimits are a coarse backstop and nothing more. RLIMIT_AS caps address
    // space, not resident memory, so it is a floor under the cgroup, not a
    // substitute for it. we set both when we can.
    const auto& r = d.resources;
    auto rlimit = [&](std::uint32_t res, std::uint64_t v) {
        b.op(OpCode::set_rlimit, SetRlimitOp{res, 0, v, v});
    };

    // try for a real cgroup first, because whether we get one decides what the
    // report may claim.
    bool have_cgroup = false;
    if (host.cgroups == cgroup::Availability::delegated &&
        (!r.memory.is_unlimited() || !r.pids.is_unlimited())) {
        auto g = cgroup::create(cgroup::probe(), r, "box");
        if (g) {
            out.cgroup = std::move(*g);
            have_cgroup = out.cgroup.valid();
        }
        // a failure here is not fatal: rlimits still apply and the report will
        // say `partial` rather than `strong`. but we must not pretend.
    }

    if (!r.memory.is_unlimited()) {
        rlimit(kRlimitAs, r.memory.value());
        if (have_cgroup && host.cgroup_memory)
            // memory.max plus memory.swap.max=0: a cap that swap can defeat is
            // not a cap.
            report.record(CapId::mem_limit, Enforcement::strong, "cgroup2 memory.max");
        else
            report.record(CapId::mem_limit, Enforcement::partial, "rlimit-as");
    }
    if (!r.pids.is_unlimited()) {
        rlimit(kRlimitNproc, r.pids.value());
        if (have_cgroup && host.cgroup_pids)
            report.record(CapId::pid_limit, Enforcement::strong, "cgroup2 pids.max");
        else
            // RLIMIT_NPROC is per-UID, not per-sandbox: another process running
            // as the same user counts against it. genuinely partial.
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
    if (!r.cpu_quota_percent.is_unlimited()) {
        if (have_cgroup && host.cgroup_cpu)
            report.record(CapId::cpu_limit, Enforcement::strong, "cgroup2 cpu.max");
        else
            // the cpu controller is frequently NOT delegated to user sessions,
            // so asking for a quota and getting nothing is common. say so.
            report.record(CapId::cpu_limit, Enforcement::none, "cpu controller not delegated");
    }

    // wall-clock is not a kernel mechanism at all: it needs a supervisor with a
    // timer, which is the loop's job. record nothing rather than imply we did.

    // -- phase: privilege drop (BEFORE landlock) ---------------------------
    // landlock_restrict_self and seccomp both require no_new_privs to already
    // be set, so this phase has to come first. it fails with a bare EPERM
    // otherwise, which is almost impossible to diagnose from the symptom.
    if (host.no_new_privs) {
        b.op(OpCode::no_new_privs, NoNewPrivsOp{0});
        // the bounding set: everything NOT in keep_caps is dropped, so a caller
        // who says nothing gets the empty set. forbidden_caps() is masked out
        // even if a caller managed to ask, because a sandbox holding
        // CAP_SYS_ADMIN is not a sandbox.
        Caps keep = d.keep_caps.without(forbidden_caps());
        b.op(OpCode::drop_caps, DropCapsOp{keep.bits()});
        if (keep.is_nothing()) {
            report.record(CapId::privilege_drop, Enforcement::strong,
                          "no_new_privs+empty bounding set");
        } else {
            // keeping any capability is a real weakening, and the report must
            // not describe it the same way as dropping everything.
            report.record(CapId::privilege_drop, Enforcement::partial,
                          "no_new_privs, some capabilities retained");
        }
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

    // devices: with a tree we mount an explicit allowlist, so /dev/mem and
    // friends are ABSENT rather than denied. without one, the best we can do is
    // whatever landlock covers, which does not mediate device nodes usefully.
    if (!building_tree)
        report.record(CapId::device_isolation, Enforcement::none,
                      "needs a mount namespace for a /dev allowlist");

    auto plan = std::move(b).build();
    if (!plan) return std::unexpected(plan.error());

    out.plan = std::move(*plan);
    out.guarantees = std::move(report).build();
    return out;
}

}  // namespace clay
