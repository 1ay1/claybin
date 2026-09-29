// claybin: the post-fork path.
//
// RULES FOR THIS FILE, all of them load-bearing:
//
//   1. no allocation. after clone() in a process that had threads, malloc can
//      deadlock outright: another thread may have held the arena lock at fork
//      time and it is never coming back to release it.
//   2. no libc calls that might allocate or take a lock. that rules out stdio,
//      std::string, iostreams, and anything in <format>.
//   3. no exceptions (the library is built -fno-exceptions anyway).
//   4. syscalls only, through raw syscall() wrappers.
//   5. never return an error to a caller that might keep running. a half-built
//      sandbox is worse than no sandbox, so any failure here is fatal to the
//      child by construction.
//
// this is why the Plan is a flat arena of POD ops: walking it needs no
// allocation, and every string it hands to a syscall is already nul-terminated
// inside the arena.
#include "claybin/plan/plan.hpp"

#if defined(__linux__)

#include <cerrno>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace clay {
namespace {

// ---- raw syscall wrappers. no libc wrappers: several of them touch errno
// ---- through TLS or take locks we cannot rely on after a fork.

inline long sys(long nr, long a = 0, long b = 0, long c = 0, long d = 0, long e = 0) {
    return ::syscall(nr, a, b, c, d, e);
}

// write a whole buffer to a path. used for uid_map/gid_map/setgroups, which
// must be written in a single write() -- the kernel rejects partial writes to
// them, so a short write is a hard failure rather than something to retry.
bool write_all(const char* path, const char* data, std::size_t len) {
    long fd = sys(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path), O_WRONLY | O_CLOEXEC, 0);
    if (fd < 0) return false;
    long n = sys(SYS_write, fd, reinterpret_cast<long>(data), static_cast<long>(len));
    sys(SYS_close, fd);
    return n == static_cast<long>(len);
}

std::size_t cstr_len(const char* s) {
    std::size_t n = 0;
    while (s[n] != '\0') ++n;
    return n;
}

// render "N N 1\n" for a uid/gid map without touching snprintf, which may
// allocate. the buffer is caller-owned and stack-allocated.
std::size_t render_identity_map(char* buf, std::size_t cap, unsigned id) {
    auto put_uint = [&](std::size_t pos, unsigned v) -> std::size_t {
        char tmp[16];
        std::size_t n = 0;
        if (v == 0) tmp[n++] = '0';
        while (v > 0) {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        for (std::size_t i = 0; i < n && pos < cap; ++i) buf[pos++] = tmp[n - 1 - i];
        return pos;
    };
    std::size_t p = 0;
    p = put_uint(p, id);
    if (p < cap) buf[p++] = ' ';
    p = put_uint(p, id);
    if (p < cap) buf[p++] = ' ';
    if (p < cap) buf[p++] = '1';
    if (p < cap) buf[p++] = '\n';
    return p;
}

// landlock syscall numbers. not in every libc's headers yet, so we use the
// numbers directly; they are stable ABI.
constexpr long kSysLandlockCreateRuleset = 444;
constexpr long kSysLandlockAddRule = 445;
constexpr long kSysLandlockRestrictSelf = 446;

// landlock's ruleset attr has GROWN across abi versions: abi 1-3 had only
// handled_access_fs, abi 4 added handled_access_net, and later abis add more
// (abi 6 scoping, and beyond). the kernel validates the size argument against
// what IT knows, so passing sizeof(our struct) means a newer kernel reads a
// truncated struct and rejects the call.
//
// so we declare it generously and pass the size matching the abi we detected,
// never more than the kernel understands.
struct LandlockRulesetAttr {
    std::uint64_t handled_access_fs;
    std::uint64_t handled_access_net;
    std::uint64_t scoped;
    std::uint64_t reserved[3];  // room for abis we do not know about yet
};

// how many bytes of the attr this abi actually understands.
constexpr std::size_t ruleset_attr_size(std::uint32_t abi) {
    if (abi >= 6) return 3 * sizeof(std::uint64_t);  // fs + net + scoped
    if (abi >= 4) return 2 * sizeof(std::uint64_t);  // fs + net
    return sizeof(std::uint64_t);                    // fs only
}
struct LandlockPathBeneathAttr {
    std::uint64_t allowed_access;
    std::int32_t parent_fd;
} __attribute__((packed));

constexpr int kLandlockRuleTypePathBeneath = 1;

}  // namespace

Status Plan::apply() const {
    // capture our identity BEFORE anything runs. once unshare(CLONE_NEWUSER)
    // succeeds we are in a namespace with no map yet, so getuid() returns the
    // overflow uid (65534) rather than who we actually are -- and writing that
    // into uid_map is an attempt to map a uid we do not own, which the kernel
    // rejects with EPERM. this line is the whole reason the first escape test
    // run failed.
    const unsigned real_uid = static_cast<unsigned>(::getuid());
    const unsigned real_gid = static_cast<unsigned>(::getgid());

    // landlock needs the ruleset fd to live across every rule op, so it is held
    // here rather than inside the loop. it is created by the FIRST landlock op
    // we see, which requires knowing the handled-access mask -- and that lives
    // on the enforce op. so the compiler emits enforce's mask up front by
    // creating the ruleset before any rule: we look ahead for it here.
    int ll_fd = -1;
    Error fail{};

    auto die = [&](Errc c, const char* mech, int err) {
        fail = Error{c, mech, err};
        return false;
    };

    // find the enforce op's masks before walking, so the ruleset exists by the
    // time the first rule op runs. one extra pass over a handful of ops, with
    // no allocation.
    {
        LandlockEnforceOp enf{};
        bool found = false;
        for_each([&](OpCode c, std::span<const std::byte> p) {
            if (c == OpCode::landlock_enforce) {
                found = decode(p, enf);
                return false;
            }
            return true;
        });
        if (found) {
            LandlockRulesetAttr attr{};
            attr.handled_access_fs = enf.handled_fs;
            attr.handled_access_net = enf.handled_net;
            attr.scoped = 0;
            // pass exactly the prefix this abi knows. a newer kernel expects a
            // bigger struct and an older one rejects extra fields, so the size
            // has to track the detected abi rather than sizeof(attr).
            std::size_t attr_size = ruleset_attr_size(enf.abi);
            long fd = sys(kSysLandlockCreateRuleset, reinterpret_cast<long>(&attr),
                          static_cast<long>(attr_size), 0);
            if (fd < 0) return std::unexpected(Error{Errc::permission_denied,
                                                     "landlock_create_ruleset", errno});
            ll_fd = static_cast<int>(fd);
        }
    }

    bool ok = for_each([&](OpCode code, std::span<const std::byte> payload) {
        switch (code) {
            case OpCode::unshare: {
                UnshareOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "unshare", 0);
                if (sys(SYS_unshare, static_cast<long>(op.flags)) < 0)
                    return die(Errc::permission_denied, "unshare", errno);
                return true;
            }
            case OpCode::write_file: {
                WriteFileOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "write_file", 0);
                const char* path = cstr(op.path);
                const char* content = cstr(op.content);
                if (!path || !content) return die(Errc::invalid_policy, "write_file", 0);

                // an empty content ref means "map my own id to itself", which
                // we cannot bake in at compile time because the plan may be
                // built by a different process than the one applying it. note
                // this uses the identity captured before the unshare.
                if (op.content.len == 0) {
                    char buf[64];
                    std::size_t plen = cstr_len(path);
                    bool is_gid = plen >= 7 && path[plen - 7] == 'g';  // .../gid_map
                    std::size_t n =
                        render_identity_map(buf, sizeof buf, is_gid ? real_gid : real_uid);
                    if (!write_all(path, buf, n))
                        return die(Errc::permission_denied, "id_map", errno);
                    return true;
                }
                if (!write_all(path, content, op.content.len))
                    return die(Errc::permission_denied, "write_file", errno);
                return true;
            }
            case OpCode::mount: {
                MountOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "mount", 0);
                const char* src = cstr(op.source);
                const char* tgt = cstr(op.target);
                const char* fst = cstr(op.fstype);
                const char* dat = op.data.len ? cstr(op.data) : nullptr;
                if (!src || !tgt || !fst) return die(Errc::invalid_policy, "mount", 0);
                if (sys(SYS_mount, reinterpret_cast<long>(src), reinterpret_cast<long>(tgt),
                        reinterpret_cast<long>(fst), static_cast<long>(op.flags),
                        reinterpret_cast<long>(dat)) < 0)
                    return die(Errc::permission_denied, "mount", errno);
                return true;
            }
            case OpCode::pivot_root: {
                PivotRootOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "pivot_root", 0);
                const char* nr = cstr(op.new_root);
                const char* po = cstr(op.put_old);
                if (!nr || !po) return die(Errc::invalid_policy, "pivot_root", 0);
                if (sys(SYS_pivot_root, reinterpret_cast<long>(nr), reinterpret_cast<long>(po)) < 0)
                    return die(Errc::permission_denied, "pivot_root", errno);
                return true;
            }
            case OpCode::umount: {
                UmountOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "umount", 0);
                const char* t = cstr(op.target);
                if (!t) return die(Errc::invalid_policy, "umount", 0);
                if (sys(SYS_umount2, reinterpret_cast<long>(t), static_cast<long>(op.flags)) < 0)
                    return die(Errc::permission_denied, "umount", errno);
                return true;
            }
            case OpCode::dup2: {
                Dup2Op op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "dup2", 0);
                if (sys(SYS_dup3, op.from, op.to, 0) < 0)
                    return die(Errc::io_error, "dup2", errno);
                return true;
            }
            case OpCode::close_range: {
                CloseRangeOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "close_range", 0);
                // a leaked fd is a capability the sandbox never agreed to grant,
                // so failure here is fatal rather than best-effort.
                if (sys(SYS_close_range, op.lo, op.hi, 0) < 0)
                    return die(Errc::io_error, "close_range", errno);
                return true;
            }
            case OpCode::set_hostname: {
                SetHostnameOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "sethostname", 0);
                const char* n = cstr(op.name);
                if (!n) return die(Errc::invalid_policy, "sethostname", 0);
                // best effort: fails without a uts namespace, which is not fatal
                sys(SYS_sethostname, reinterpret_cast<long>(n),
                    static_cast<long>(cstr_len(n)));
                return true;
            }
            case OpCode::chdir: {
                ChdirOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "chdir", 0);
                const char* p = cstr(op.path);
                if (!p) return die(Errc::invalid_policy, "chdir", 0);
                if (sys(SYS_chdir, reinterpret_cast<long>(p)) < 0)
                    return die(Errc::io_error, "chdir", errno);
                return true;
            }
            case OpCode::set_rlimit: {
                SetRlimitOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "setrlimit", 0);
                struct rlimit64 {
                    std::uint64_t cur, max;
                } rl{op.soft, op.hard};
                if (sys(SYS_prlimit64, 0, op.resource, reinterpret_cast<long>(&rl), 0) < 0)
                    return die(Errc::permission_denied, "setrlimit", errno);
                return true;
            }
            case OpCode::set_ids: {
                SetIdsOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "setids", 0);
                // gid first: after setuid we may no longer be allowed to setgid.
                if (sys(SYS_setgid, op.gid) < 0)
                    return die(Errc::permission_denied, "setgid", errno);
                if (sys(SYS_setuid, op.uid) < 0)
                    return die(Errc::permission_denied, "setuid", errno);
                return true;
            }
            case OpCode::landlock_rule: {
                LandlockRuleOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "landlock", 0);
                if (ll_fd < 0) return die(Errc::invalid_policy, "landlock: rule before enforce", 0);
                const char* p = cstr(op.path);
                if (!p) return die(Errc::invalid_policy, "landlock", 0);

                long fd = sys(SYS_openat, AT_FDCWD, reinterpret_cast<long>(p),
                              O_PATH | O_CLOEXEC, 0);
                if (fd < 0) {
                    // a grant for a path that does not exist is not an escape
                    // risk -- there is nothing to reach -- so skip it rather
                    // than refusing to start.
                    return true;
                }
                LandlockPathBeneathAttr attr{op.allowed, static_cast<std::int32_t>(fd)};
                long rc = sys(kSysLandlockAddRule, ll_fd, kLandlockRuleTypePathBeneath,
                              reinterpret_cast<long>(&attr), 0);
                sys(SYS_close, fd);
                if (rc < 0) return die(Errc::permission_denied, "landlock_add_rule", errno);
                return true;
            }
            case OpCode::landlock_enforce: {
                LandlockEnforceOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "landlock", 0);
                if (ll_fd < 0) return die(Errc::invalid_policy, "landlock: no ruleset", 0);
                if (sys(kSysLandlockRestrictSelf, ll_fd, 0) < 0)
                    return die(Errc::permission_denied, "landlock_restrict_self", errno);
                sys(SYS_close, ll_fd);
                ll_fd = -1;
                return true;
            }
            case OpCode::drop_caps: {
                DropCapsOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "drop_caps", 0);
                // drop the bounding set so no exec can ever regain a capability.
                // CAP_LAST_CAP moves with kernels; walk until EINVAL.
                for (int cap = 0; cap <= 63; ++cap) {
                    if (op.keep & (1ull << cap)) continue;
                    if (::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno == EINVAL) break;
                }
                return true;
            }
            case OpCode::no_new_privs: {
                if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                    return die(Errc::permission_denied, "no_new_privs", errno);
                return true;
            }
            case OpCode::seccomp_install: {
                SeccompInstallOp op{};
                if (!decode(payload, op)) return die(Errc::invalid_policy, "seccomp", 0);
                auto blob = this->blob(op.program);
                if (blob.empty() || op.insn_count == 0)
                    return die(Errc::invalid_policy, "seccomp: empty program", 0);

                struct sock_fprog prog {
                    static_cast<unsigned short>(op.insn_count),
                        reinterpret_cast<struct sock_filter*>(
                            const_cast<std::byte*>(blob.data()))
                };
                if (sys(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
                        reinterpret_cast<long>(&prog)) < 0)
                    return die(Errc::permission_denied, "seccomp", errno);
                return true;
            }
        }
        return die(Errc::invalid_policy, "unknown opcode", 0);
    });

    // defensive: a plan with landlock rules but no enforce op would leave this
    // open. well_ordered() plus compile() make that unreachable, but an fd leak
    // into the guest is a capability leak, so close it anyway.
    if (ll_fd >= 0) sys(SYS_close, ll_fd);

    if (!ok) return std::unexpected(fail);
    return {};
}

}  // namespace clay

#else  // not linux

namespace clay {

Status Plan::apply() const {
    return std::unexpected(Error{Errc::unsupported, "plan::apply: linux only"});
}

}  // namespace clay

#endif
