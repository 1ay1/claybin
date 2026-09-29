// claybin: the policy, with phase encoded in the type.
//
//   Policy<Draft>   mutable, can grant authority, cannot be run
//     | seal() &&   consumes the draft
//   Policy<Sealed>  immutable, meet-able, auditable, compilable
//
// builder methods are rvalue-qualified so a draft threads linearly through the
// chain. you cannot keep a reference to a half-built policy and mutate it after
// someone else sealed a copy.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "claybin/core/error.hpp"
#include "claybin/core/lattice.hpp"
#include "claybin/policy/filesystem.hpp"
#include "claybin/policy/resources.hpp"
#include "claybin/policy/syscalls.hpp"

namespace clay {

// phase tags
struct Draft {};
struct Sealed {};

template <class Phase>
class Policy;

// ---------------------------------------------------------------------------
// process / privilege authority
// ---------------------------------------------------------------------------

struct ProcOpsTag {};
using ProcOps = Flags<ProcOpsTag, std::uint32_t>;

inline constexpr ProcOps kProcFork{1u << 0};
inline constexpr ProcOps kProcExec{1u << 1};
inline constexpr ProcOps kProcPtrace{1u << 2};
inline constexpr ProcOps kProcSignalSelfTree{1u << 3};
inline constexpr ProcOps kProcSetuid{1u << 4};
inline constexpr ProcOps kProcNewNamespace{1u << 5};

// how strong a boundary the caller is asking for. not a hint: compile() fails
// rather than silently downgrading.
enum class Isolation : std::uint8_t {
    process,           // namespaces + landlock + seccomp + cgroup
    hardened_process,  // + strict syscall profile, no new namespaces, empty net ns
    microvm,           // separate kernel
};

struct EnvVar {
    std::string key;
    std::string value;
    friend bool operator==(const EnvVar&, const EnvVar&) = default;
};

// the phase-independent payload. the Policy<Phase> wrapper adds the typestate.
struct PolicyData {
    FsAuthority fs{};
    NetAuthority net{};
    ResourceLimits resources{};
    SyscallPolicy syscalls{};
    ProcOps proc{};
    Isolation isolation{Isolation::process};

    // environment is authority too: PATH, LD_PRELOAD and friends are an
    // execution channel. default is empty, opt in by name.
    std::vector<EnvVar> env{};
    bool env_cleared{true};

    std::string hostname{"sandbox"};
    std::string workdir{"/"};

    PolicyData meet(const PolicyData& o) const {
        PolicyData r;
        r.fs = fs.meet(o.fs);
        r.net = net.meet(o.net);
        r.resources = resources.meet(o.resources);
        r.syscalls = syscalls.meet(o.syscalls);
        r.proc = proc.meet(o.proc);
        // stronger isolation wins, and stronger is the larger enum value.
        r.isolation = isolation > o.isolation ? isolation : o.isolation;
        r.env_cleared = env_cleared || o.env_cleared;
        // env intersects: a var survives only if both sides agree on it exactly.
        for (const auto& a : env)
            for (const auto& b : o.env)
                if (a.key == b.key && a.value == b.value) r.env.push_back(a);
        r.hostname = hostname;
        r.workdir = workdir;
        return r;
    }

    bool subsumes(const PolicyData& o) const {
        return fs.subsumes(o.fs) && net.subsumes(o.net) && resources.subsumes(o.resources) &&
               syscalls.subsumes(o.syscalls) && proc.subsumes(o.proc) && isolation <= o.isolation;
    }

    friend bool operator==(const PolicyData&, const PolicyData&) = default;
};

// ---------------------------------------------------------------------------
// Policy<Draft>: grants allowed
// ---------------------------------------------------------------------------

template <>
class Policy<Draft> {
  public:
    // a fresh draft grants no AUTHORITY: no filesystem, no network, no
    // syscalls beyond what a profile adds. you build up from nothing.
    //
    // resources are deliberately NOT bottom. a limit is a ceiling, so the
    // lattice bottom is 0, and 0 means "cannot allocate a single page" --
    // RLIMIT_AS=0 makes execve fail with EACCES before the program ever runs.
    // bottom is the right identity for permissions and the wrong default for
    // ceilings, so a draft starts unlimited and the caller tightens explicitly.
    Policy() { data_.resources = ResourceLimits::everything(); }

    // -- filesystem ---------------------------------------------------------
    Policy&& read(std::string_view p) && {
        data_.fs.grant(p, FileRights::read());
        return std::move(*this);
    }
    Policy&& read_write(std::string_view p) && {
        data_.fs.grant(p, FileRights::write());
        return std::move(*this);
    }
    Policy&& execute(std::string_view p) && {
        data_.fs.grant(p, FileRights::exec());
        return std::move(*this);
    }
    Policy&& grant(std::string_view p, FileRights r) && {
        data_.fs.grant(p, r);
        return std::move(*this);
    }
    // punch a hole inside an already-granted subtree.
    Policy&& deny(std::string_view p) && {
        data_.fs.deny(p);
        return std::move(*this);
    }

    // -- network ------------------------------------------------------------
    Policy&& connect(std::string host, std::uint16_t port) && {
        data_.net.allow(std::move(host), port, kNetConnect);
        return std::move(*this);
    }
    Policy&& unix_sockets() && {
        data_.net.allow_any(kNetUnixSocket);
        return std::move(*this);
    }

    // -- resources ----------------------------------------------------------
    Policy&& memory(Bytes b) && {
        data_.resources.memory = b;
        return std::move(*this);
    }
    Policy&& processes(std::uint64_t n) && {
        data_.resources.pids = Count{n};
        return std::move(*this);
    }
    Policy&& open_files(std::uint64_t n) && {
        data_.resources.open_files = Count{n};
        return std::move(*this);
    }
    Policy&& cpu_time(Nanos n) && {
        data_.resources.cpu_time = n;
        return std::move(*this);
    }
    Policy&& wall_clock(Nanos n) && {
        data_.resources.wall_clock = n;
        return std::move(*this);
    }

    // -- syscalls -----------------------------------------------------------
    Policy&& syscall_profile(SyscallPolicy p) && {
        data_.syscalls = std::move(p);
        return std::move(*this);
    }

    // -- process ------------------------------------------------------------
    Policy&& allow_fork() && {
        data_.proc = ProcOps{data_.proc.unsafe_join(kProcFork)};
        return std::move(*this);
    }
    Policy&& allow_exec() && {
        data_.proc = ProcOps{data_.proc.unsafe_join(kProcExec)};
        return std::move(*this);
    }

    // -- environment --------------------------------------------------------
    Policy&& env(std::string key, std::string value) && {
        data_.env.push_back({std::move(key), std::move(value)});
        return std::move(*this);
    }
    Policy&& workdir(std::string p) && {
        data_.workdir = path::normalize(p);
        return std::move(*this);
    }
    Policy&& isolation(Isolation lvl) && {
        data_.isolation = lvl;
        return std::move(*this);
    }

    // consumes the draft. after this there is no way back to a mutable policy,
    // so nothing can be widened behind a holder's back.
    Policy<Sealed> seal() &&;

  private:
    PolicyData data_;
};

// ---------------------------------------------------------------------------
// Policy<Sealed>: immutable, composable by meet only
// ---------------------------------------------------------------------------

template <>
class Policy<Sealed> {
  public:
    static Policy nothing() {
        PolicyData d;
        d.fs = FsAuthority::nothing();
        d.net = NetAuthority::nothing();
        d.resources = ResourceLimits::nothing();
        d.syscalls = SyscallPolicy::nothing();
        d.proc = ProcOps::nothing();
        d.isolation = Isolation::microvm;  // bottom authority = strongest boundary
        return Policy{std::move(d)};
    }

    static Policy everything() {
        PolicyData d;
        d.fs = FsAuthority::everything();
        d.net = NetAuthority::everything();
        d.resources = ResourceLimits::everything();
        d.syscalls = SyscallPolicy::everything();
        d.proc = ProcOps::everything();
        d.isolation = Isolation::process;
        d.env_cleared = false;
        return Policy{std::move(d)};
    }

    Policy meet(const Policy& o) const { return Policy{data_.meet(o.data_)}; }
    bool subsumes(const Policy& o) const { return data_.subsumes(o.data_); }
    bool is_nothing() const {
        return data_.fs.is_nothing() && data_.net.is_nothing() && data_.proc.is_nothing();
    }

    const PolicyData& data() const { return data_; }

    // reopen for editing. explicit and loud on purpose: it is the only way back
    // to a phase where authority can grow, so it should be greppable.
    Policy<Draft> unseal_for_editing() const;

    friend bool operator==(const Policy& a, const Policy& b) { return a.data_ == b.data_; }

  private:
    friend class Policy<Draft>;
    explicit Policy(PolicyData d) : data_(std::move(d)) {}
    PolicyData data_;
};

inline Policy<Sealed> Policy<Draft>::seal() && {
    data_.fs.normalize();
    return Policy<Sealed>{std::move(data_)};
}

static_assert(Lattice<Policy<Sealed>>);

}  // namespace clay
