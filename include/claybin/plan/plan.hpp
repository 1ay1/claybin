// claybin: the compiled plan.
//
// everything that can fail, allocate, take a lock, or call into libc happens
// while BUILDING a plan. applying one is a loop of raw syscalls: no malloc, no
// locks, no libc paths that touch the allocator, no unbounded work. that is
// what makes it async-signal-safe after clone(), and it is why spawning from an
// already-compiled plan costs about what the kernel costs.
//
// the arena is position-independent: ops refer to strings by (offset, length)
// into the same buffer, never by pointer. so a plan can be memcpy'd, placed in
// shared memory, or written down a pipe and applied by a different process.
//
// this header is pure. encoding, decoding and the ordering checks are all
// testable on a machine with no seccomp, no landlock and no kernel headers.
// only apply() is linux, and it lives in its own translation unit.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "claybin/core/error.hpp"

namespace clay {

// ---------------------------------------------------------------------------
// phases
//
// the ORDER of setup steps is a security property, not a style choice:
//
//   - mounts must happen after the namespaces that contain them
//   - landlock must come after mounts, or it locks down a tree that is about
//     to be replaced
//   - no_new_privs must precede BOTH landlock and seccomp. the kernel requires
//     it for landlock_restrict_self and for an unprivileged seccomp filter, and
//     without it an suid exec re-grants privilege across the wall we just
//     built. this cost an afternoon: landlock_restrict_self returns EPERM with
//     no explanation when nnp is unset, which surfaces later as an EACCES from
//     execve and looks exactly like a missing path grant.
//   - seccomp goes LAST, because a filter that denies mount/openat would
//     otherwise block the rest of our own setup
//
// so every op carries a phase, and a plan is only valid if phases are
// non-decreasing. that turns "we remembered the right order" into something
// the compiler checks and a test can prove for every policy.
// ---------------------------------------------------------------------------

enum class Phase : std::uint8_t {
    namespaces = 0,  // unshare, uid/gid maps
    mounts = 1,      // mount, pivot_root, umount
    fds = 2,         // dup2, close_range
    process = 3,     // hostname, chdir, rlimits, uid/gid
    privdrop = 4,    // no_new_privs, capability drop -- REQUIRED before landlock
    landlock = 5,    // filesystem/network restriction
    seccomp = 6,     // the last wall
    count_,
};

constexpr const char* to_string(Phase p) {
    switch (p) {
        case Phase::namespaces: return "namespaces";
        case Phase::mounts: return "mounts";
        case Phase::fds: return "fds";
        case Phase::process: return "process";
        case Phase::privdrop: return "privdrop";
        case Phase::landlock: return "landlock";
        case Phase::seccomp: return "seccomp";
        case Phase::count_: break;
    }
    return "?";
}

enum class OpCode : std::uint16_t {
    unshare = 1,
    write_file,     // uid_map, gid_map, setgroups: small writes with no libc
    mount,
    // remount a bind AND every submount under it, OR-ing flags onto whatever
    // each already has. a plain bind does not apply its flags, and a plain
    // remount only touches the top mount -- so without this a --ro-bind of a
    // tree containing its own submounts leaves those submounts WRITABLE.
    remount_recursive,
    mkdir_p,        // create a mount point (and its parents) inside the new tree
    touch,          // create an empty file as a bind target for a device node
    bind_target,    // create a mount point matching the SOURCE's kind (dir or file)
    symlink_at,     // /lib -> usr/lib, the usr-merge layout every distro needs
    // copy a caller-held fd's contents into the tree. with the bind flag set,
    // the bytes go to a temp file which is bound at `dest` and then UNLINKED, so
    // the backing file has no name the guest could open.
    write_fd_content,
    pivot_root,
    // the second half of bubblewrap's pivot dance: chdir into newroot, then
    // pivot_root(".", ".") so the old root stacks on top of itself and can be
    // detached leaving NO directory behind in the guest's tree.
    pivot_into_newroot,
    umount,
    dup2,
    close_range,    // close inherited descriptors. see Phase::fds for the order
                    // reasoning: this has to be LATE, after every fd the plan
                    // itself needs has been used.
    set_hostname,
    chdir,
    new_session,      // setsid: detach from the host's controlling terminal
    die_with_parent,  // PR_SET_PDEATHSIG, so an orphan cannot linger
    set_rlimit,
    set_ids,
    landlock_rule,
    // landlock network rule (abi 4+): mediate TCP bind/connect by PORT. a real
    // second wall over a netns, which is all-or-nothing.
    landlock_net_rule,
    landlock_enforce,
    drop_caps,
    no_new_privs,
    seccomp_install,
};

constexpr Phase phase_of(OpCode c) {
    switch (c) {
        case OpCode::unshare:
        case OpCode::write_file: return Phase::namespaces;
        case OpCode::mount:
        case OpCode::remount_recursive:
        case OpCode::mkdir_p:
        case OpCode::touch:
        case OpCode::bind_target:
        case OpCode::symlink_at:
        case OpCode::write_fd_content:
        case OpCode::pivot_root:
        case OpCode::pivot_into_newroot:
        case OpCode::umount: return Phase::mounts;
        case OpCode::dup2: return Phase::fds;
        // close_range lives in privdrop, not fds. it has to run AFTER the mount
        // phase (which uses --file source fds) and after the landlock ruleset fd
        // exists, or it closes the very descriptors the rest of the plan needs.
        // putting it next to the other "give up capability" ops is also the
        // honest description of what it is.
        case OpCode::close_range: return Phase::privdrop;
        case OpCode::set_hostname:
        case OpCode::chdir:
        case OpCode::new_session:
        case OpCode::die_with_parent:
        case OpCode::set_rlimit:
        case OpCode::set_ids: return Phase::process;
        case OpCode::landlock_rule:
        case OpCode::landlock_net_rule:
        case OpCode::landlock_enforce: return Phase::landlock;
        case OpCode::drop_caps:
        case OpCode::no_new_privs: return Phase::privdrop;
        case OpCode::seccomp_install: return Phase::seccomp;
    }
    return Phase::seccomp;
}

constexpr const char* to_string(OpCode c) {
    switch (c) {
        case OpCode::unshare: return "unshare";
        case OpCode::write_file: return "write_file";
        case OpCode::mount: return "mount";
        case OpCode::remount_recursive: return "remount_rec";
        case OpCode::mkdir_p: return "mkdir_p";
        case OpCode::touch: return "touch";
        case OpCode::bind_target: return "bind_target";
        case OpCode::symlink_at: return "symlink";
        case OpCode::write_fd_content: return "write_fd";
        case OpCode::pivot_root: return "pivot_root";
        case OpCode::pivot_into_newroot: return "pivot_newroot";
        case OpCode::umount: return "umount";
        case OpCode::dup2: return "dup2";
        case OpCode::close_range: return "close_range";
        case OpCode::set_hostname: return "set_hostname";
        case OpCode::chdir: return "chdir";
        case OpCode::new_session: return "new_session";
        case OpCode::die_with_parent: return "die_with_parent";
        case OpCode::set_rlimit: return "set_rlimit";
        case OpCode::set_ids: return "set_ids";
        case OpCode::landlock_rule: return "landlock_rule";
        case OpCode::landlock_net_rule: return "landlock_net";
        case OpCode::landlock_enforce: return "landlock_enforce";
        case OpCode::drop_caps: return "drop_caps";
        case OpCode::no_new_privs: return "no_new_privs";
        case OpCode::seccomp_install: return "seccomp_install";
    }
    return "?";
}

// a blob living inside the arena. an offset, never a pointer, so the arena
// stays relocatable. strings are stored with a trailing nul so the post-fork
// path can hand `arena + off` straight to a syscall with no copy.
struct Ref {
    std::uint32_t off{0};
    std::uint32_t len{0};

    friend constexpr bool operator==(const Ref&, const Ref&) = default;
};

// every op starts with this. `size` covers the header plus payload, so a
// decoder can skip an op it does not know without understanding it.
struct OpHeader {
    std::uint16_t code;
    std::uint16_t size;
    std::uint32_t _pad;
};
static_assert(sizeof(OpHeader) == 8);

// ---- payloads. all fields fixed-width, 8-byte aligned, no padding holes ----

struct UnshareOp {
    std::uint64_t flags;
};
struct WriteFileOp {
    Ref path;
    Ref content;
};
struct MountOp {
    Ref source;
    Ref target;
    Ref fstype;
    Ref data;
    std::uint64_t flags;
};
struct PivotRootOp {
    Ref new_root;
    Ref put_old;
};
struct MkdirOp {
    Ref path;
    std::uint32_t mode;
    std::uint32_t _pad;
};
struct SymlinkOp {
    Ref target;
    Ref linkpath;
};
// create a mount point whose KIND matches the source: a directory for a
// directory, an empty regular file for a file. binding a file onto a directory
// fails with ENOTDIR, and the source can only be stat'd on the machine that
// applies the plan.
struct BindTargetOp {
    Ref source;
    Ref dest;
};
// copy `fd`'s contents to `dest`. flags bit 0 = bind it in and unlink the
// backing file, bit 1 = make that bind read-only.
struct WriteFdContentOp {
    Ref dest;
    std::int32_t fd;
    std::uint32_t perms;
    std::uint32_t flags;
    std::uint32_t _pad;
};
struct UmountOp {
    Ref target;
    std::uint64_t flags;
};
// remount `target` and everything under it, adding `add_flags` to each mount's
// existing flags. `optional` mirrors the mount op's bit.
struct RemountRecursiveOp {
    Ref target;
    std::uint64_t add_flags;
};
struct Dup2Op {
    std::int32_t from;
    std::int32_t to;
};
struct CloseRangeOp {
    std::uint32_t lo;
    std::uint32_t hi;
    // descriptors to spare. close_range() itself cannot express an exception, so
    // apply() walks /proc/self/fd when this is non-empty. small and fixed: the
    // only things that ever need sparing are spawn's report pipe and any --file
    // source not yet copied.
    std::uint32_t keep_count;
    std::uint32_t keep[13];
};

// a placeholder in CloseRangeOp::keep that spawn() rewrites to its own report
// pipe fd at apply time. the compiler cannot know that number -- the pipe does
// not exist until spawn runs -- so it reserves a slot instead.
inline constexpr std::uint32_t kReportFdSentinel = 0xfffffffeu;
// likewise for the broker relay pipe, which the guest writes its listener fd
// number to after the phase that closes inherited descriptors.
inline constexpr std::uint32_t kRelayFdSentinel = 0xfffffffdu;
struct SetHostnameOp {
    Ref name;
};
struct ChdirOp {
    Ref path;
};
struct SetRlimitOp {
    std::uint32_t resource;
    std::uint32_t _pad;
    std::uint64_t soft;
    std::uint64_t hard;
};
struct SetIdsOp {
    std::uint32_t uid;
    std::uint32_t gid;
};
struct LandlockRuleOp {
    Ref path;
    std::uint64_t allowed;  // landlock access bits
};
// a network rule: which TCP operations are permitted on one port.
struct LandlockNetRuleOp {
    std::uint64_t allowed;
    std::uint16_t port;
    std::uint16_t _pad[3];
};
struct LandlockEnforceOp {
    std::uint64_t handled_fs;   // access rights the ruleset governs
    std::uint64_t handled_net;
    std::uint32_t abi;          // the abi we compiled for
    std::uint32_t _pad;
};
struct DropCapsOp {
    std::uint64_t keep;  // bounding-set bits to retain; normally 0
};
struct NoNewPrivsOp {
    std::uint64_t _reserved;
};
struct SeccompInstallOp {
    Ref program;            // the BPF instructions, inline in the arena
    std::uint32_t insn_count;
    // bit 0: the policy contains a `notify` action, so ask the kernel for a
    // listener fd (SECCOMP_FILTER_FLAG_NEW_LISTENER) rather than installing the
    // filter silently.
    std::uint32_t flags;
};

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

class PlanBuilder;

class Plan {
  public:
    Plan() = default;

    std::span<const std::byte> bytes() const { return arena_; }
    std::size_t size() const { return arena_.size(); }
    bool empty() const { return arena_.empty(); }

    // resolve a Ref to a nul-terminated C string inside the arena. returns
    // nullptr if the ref is out of bounds or not nul-terminated, which the
    // post-fork path treats as a hard failure rather than reading past the end.
    const char* cstr(Ref r) const {
        if (r.off + r.len + 1 > arena_.size()) return nullptr;
        const char* p = reinterpret_cast<const char*>(arena_.data()) + r.off;
        if (p[r.len] != '\0') return nullptr;
        return p;
    }

    std::span<const std::byte> blob(Ref r) const {
        if (r.off + r.len > arena_.size()) return {};
        return std::span<const std::byte>{arena_.data() + r.off, r.len};
    }

    // walk the ops. `fn(OpCode, payload_span)`; stops and returns false if the
    // stream is malformed.
    template <class Fn>
    bool for_each(Fn&& fn) const {
        std::size_t pos = ops_off_;
        while (pos + sizeof(OpHeader) <= arena_.size()) {
            OpHeader h{};
            std::memcpy(&h, arena_.data() + pos, sizeof h);
            if (h.size < sizeof(OpHeader)) return false;
            if (pos + h.size > arena_.size()) return false;
            std::span<const std::byte> payload{arena_.data() + pos + sizeof(OpHeader),
                                               h.size - sizeof(OpHeader)};
            if (!fn(static_cast<OpCode>(h.code), payload)) return false;
            pos += h.size;
        }
        return pos == arena_.size();
    }

    std::size_t op_count() const {
        std::size_t n = 0;
        for_each([&](OpCode, std::span<const std::byte>) {
            ++n;
            return true;
        });
        return n;
    }

    // phases must be non-decreasing. this is the ordering invariant spelled out
    // at the top of the file, checkable without running anything.
    bool well_ordered() const {
        Phase last = Phase::namespaces;
        bool ok = true;
        for_each([&](OpCode c, std::span<const std::byte>) {
            Phase p = phase_of(c);
            if (p < last) {
                ok = false;
                return false;
            }
            last = p;
            return true;
        });
        return ok;
    }

    bool has(OpCode want) const {
        bool found = false;
        for_each([&](OpCode c, std::span<const std::byte>) {
            if (c == want) found = true;
            return !found;
        });
        return found;
    }

    // decode one payload. by value + memcpy, so alignment is never assumed.
    template <class T>
    static bool decode(std::span<const std::byte> payload, T& out) {
        if (payload.size() < sizeof(T)) return false;
        std::memcpy(&out, payload.data(), sizeof(T));
        return true;
    }

    // apply the plan in the current process. POST-FORK ONLY: async-signal-safe,
    // allocation-free, and it must not be called on a process you want to keep.
    // defined in src/linux/apply.cpp; other platforms get a stub that refuses.
    Status apply() const { return apply_range(Phase::namespaces, Phase::count_); }

    // apply only the ops strictly before `stop`. needed because entering a pid
    // namespace requires a fork between the namespace phase and the mount
    // phase: unshare(CLONE_NEWPID) makes our CHILDREN members, not us, and
    // mounting procfs requires membership.
    Status apply_until(Phase stop) const { return apply_range(Phase::namespaces, stop); }

    // apply the ops from `start` onward.
    Status apply_from(Phase start) const { return apply_range(start, Phase::count_); }

    Status apply_range(Phase first, Phase last) const;

    // tell apply() which fd the kReportFdSentinel slot stands for. set by
    // spawn() in the child, before apply, because the pipe does not exist when
    // the plan is compiled.
    static void set_report_fd(int fd);
    static void set_relay_fd(int fd);

    // take the seccomp listener fd, if the policy asked for one. valid only in
    // the child, immediately after apply(); spawn() passes it to the supervisor.
    static int take_notify_fd();

  private:
    friend class PlanBuilder;
    std::vector<std::byte> arena_;
    std::uint32_t ops_off_{0};  // strings are interned below this point
};

// ---------------------------------------------------------------------------
// PlanBuilder: all the fallible work lives here, ahead of the fork
// ---------------------------------------------------------------------------

class PlanBuilder {
  public:
    PlanBuilder() = default;

    // intern a string with a trailing nul so the post-fork path can pass it
    // straight to a syscall. identical strings are shared.
    Ref intern(std::string_view s) {
        for (const auto& e : interned_)
            if (e.first == s) return e.second;
        Ref r{static_cast<std::uint32_t>(strings_.size()), static_cast<std::uint32_t>(s.size())};
        strings_.insert(strings_.end(), reinterpret_cast<const std::byte*>(s.data()),
                        reinterpret_cast<const std::byte*>(s.data()) + s.size());
        strings_.push_back(std::byte{0});
        interned_.emplace_back(std::string(s), r);
        return r;
    }

    Ref intern_blob(std::span<const std::byte> b) {
        Ref r{static_cast<std::uint32_t>(strings_.size()), static_cast<std::uint32_t>(b.size())};
        strings_.insert(strings_.end(), b.begin(), b.end());
        strings_.push_back(std::byte{0});  // keep cstr() usable on any ref
        return r;
    }

    template <class T>
    PlanBuilder& op(OpCode code, const T& payload) {
        Phase p = phase_of(code);
        if (p < last_phase_) {
            // a caller emitted ops out of order. record it rather than asserting:
            // build() turns it into an error the caller has to handle.
            ordering_broken_ = true;
        } else {
            last_phase_ = p;
        }
        OpHeader h{static_cast<std::uint16_t>(code),
                   static_cast<std::uint16_t>(sizeof(OpHeader) + sizeof(T)), 0};
        append(&h, sizeof h);
        append(&payload, sizeof payload);
        return *this;
    }

    Result<Plan> build() && {
        if (ordering_broken_)
            return std::unexpected(
                Error{Errc::invalid_policy, "plan: ops emitted out of phase order"});

        Plan p;
        // strings first, then ops. refs are offsets from the arena base, and
        // since strings occupy the front, their offsets are already correct.
        p.arena_.reserve(strings_.size() + ops_.size());
        p.arena_.insert(p.arena_.end(), strings_.begin(), strings_.end());
        p.ops_off_ = static_cast<std::uint32_t>(p.arena_.size());
        p.arena_.insert(p.arena_.end(), ops_.begin(), ops_.end());

        if (!p.well_ordered())
            return std::unexpected(Error{Errc::invalid_policy, "plan: not well ordered"});
        return p;
    }

  private:
    void append(const void* src, std::size_t n) {
        const auto* b = static_cast<const std::byte*>(src);
        ops_.insert(ops_.end(), b, b + n);
    }

    std::vector<std::byte> strings_;
    std::vector<std::byte> ops_;
    std::vector<std::pair<std::string, Ref>> interned_;
    Phase last_phase_{Phase::namespaces};
    bool ordering_broken_{false};
};

}  // namespace clay
