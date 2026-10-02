// the macOS backend's apply step: probe the host, and fork/sandbox/exec.
//
// everything in here is impure and macOS-only, which is exactly why it is a
// separate file from compile.cpp. the split mirrors linux (compile.cpp pure,
// probe.cpp + apply.cpp impure) so the testable surface stays the same shape
// on both platforms.
//
// THE CHILD-SIDE RULE, which is the whole reason this file is delicate: after
// fork() in a multithreaded process only async-signal-safe functions may be
// called. no malloc, no std::string, no iostream. every buffer the child
// touches is prepared in the parent and read-only afterwards. the one
// deliberate exception is sandbox_init(), which does allocate -- there is no
// async-signal-safe way to enter seatbelt, Apple provides no alternative, and
// every sandbox on this platform (including Chrome's) takes the same risk. it
// is called FIRST, before the fd shuffle, to keep the window as small as
// possible.
#include "claybin/macos/backend.hpp"

#if defined(__APPLE__)

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <spawn.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// the environment, for the inherit case. darwin does not declare `environ` in
// a header for a non-main binary, so take it from the documented accessor.
#include <crt_externs.h>
#define claybin_environ (*_NSGetEnviron())

// sandbox_init(3) is deprecated in the public headers but still exported by
// libSystem and still the mechanism every sandbox on this platform uses.
// declared here rather than including <sandbox.h> so the deprecation attribute
// does not turn into a warning-as-error in a caller's build, and so this file
// states exactly which symbols it depends on.
extern "C" {
int sandbox_init(const char* profile, uint64_t flags, char** errorbuf);
void sandbox_free_error(char* errorbuf);
}

#endif  // __APPLE__

namespace clay::macos {

#if defined(__APPLE__)

namespace {

// read an integer sysctl by name. returns false on any failure, so a missing
// knob is never mistaken for a permissive value -- same discipline as the
// linux probe's read_small().
bool sysctl_u32(const char* name, std::uint32_t& out) {
    char buf[64]{};
    std::size_t len = sizeof(buf) - 1;
    if (::sysctlbyname(name, buf, &len, nullptr, 0) != 0) return false;
    // kern.osrelease is a string like "24.1.0"; take the leading integer.
    char* end = nullptr;
    const unsigned long v = std::strtoul(buf, &end, 10);
    if (end == buf) return false;
    out = static_cast<std::uint32_t>(v);
    return true;
}

// does sandbox_init actually work here? the honest answer needs a real call:
// the symbol is present on every mac, but a profile can be refused by a host
// with a restrictive configuration, and finding that out at spawn time means
// finding it out on the user's machine.
//
// `(version 1)(allow default)` is the cheapest valid profile. it grants
// everything, so entering it in a probe process would be pointless -- which is
// why this only COMPILES the profile, in a throwaway child, and never applies
// one to the caller. a sandbox is irreversible: once this process enters a
// profile it cannot leave, so probing in-process would confine agentty itself.
bool probe_seatbelt() {
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid == 0) {
        char* err = nullptr;
        const int rc = ::sandbox_init("(version 1)(allow default)", 0, &err);
        if (err) ::sandbox_free_error(err);
        ::_exit(rc == 0 ? 0 : 1);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// async-signal-safe write of a fixed string. used only on the child's error
// path, where printf is forbidden.
void safe_write(int fd, const char* msg) {
    ::write(fd, msg, std::strlen(msg));
}

}  // namespace

HostCapabilities probe_host() {
    HostCapabilities h;

    std::uint32_t darwin = 0;
    if (sysctl_u32("kern.osrelease", darwin)) h.darwin_major = darwin;

    h.seatbelt = probe_seatbelt();
    if (h.seatbelt) {
        // the SBPL dialect has been stable since 10.7 (darwin 11), which is
        // older than any mac that can run a c++23 binary. gated anyway rather
        // than assumed: a probe that cannot fail is not a probe.
        h.sbpl_path_filters = h.darwin_major >= 11;
        h.sbpl_network_filters = h.darwin_major >= 11;
        h.sbpl_process_filters = h.darwin_major >= 11;
    }

    h.rlimits = true;  // POSIX; present on every darwin.

    // Hypervisor.framework needs an entitlement to USE, but its presence is
    // what compile() reports on when refusing a microvm policy.
    h.hypervisor = ::access("/System/Library/Frameworks/Hypervisor.framework", F_OK) == 0;

    return h;
}

Result<Spawned> spawn(const Compiled& compiled, const SpawnRequest& req) {
    if (req.program == nullptr || req.argv == nullptr)
        return std::unexpected(Error{Errc::invalid_policy, "macos-spawn"});

    // ---- everything the child needs, prepared in the PARENT ---------------
    //
    // the child cannot allocate, so the profile text, the rlimit array and the
    // workdir are all captured as raw pointers into parent-owned storage that
    // outlives the fork. `compiled` is const and by reference, so these stay
    // valid for the whole call.
    const char* profile = compiled.use_seatbelt ? compiled.profile.c_str() : nullptr;
    const char* workdir = req.workdir.empty() ? nullptr : req.workdir.c_str();

    // RLIMIT_* from <sys/resource.h>, resolved here rather than in compile.cpp
    // so the pure translation stays free of platform headers. the mapping is
    // asserted against the constants compile.cpp used; a mismatch would mean
    // silently applying the wrong limit, which is worse than not applying one.
    static_assert(RLIMIT_CPU == 0 && RLIMIT_CORE == 4 && RLIMIT_AS == 5 &&
                      RLIMIT_NPROC == 7 && RLIMIT_NOFILE == 8,
                  "darwin RLIMIT_* numbering changed; compile.cpp's constants are stale");

    const pid_t pid = ::fork();
    if (pid < 0) return std::unexpected(Error{Errc::spawn_failed, "fork", errno});

    if (pid == 0) {
        // ================= CHILD: async-signal-safe only ===================

        // reset every signal disposition. an inherited SIG_IGN survives exec
        // and silently changes the guest's behaviour -- a program that cannot
        // be interrupted is a supervise loop that cannot time it out.
        for (int s = 1; s < NSIG; ++s) ::signal(s, SIG_DFL);
        sigset_t empty;
        // NOT ::sigemptyset -- darwin defines it as a MACRO, and a qualified
        // call to a macro is `::(...)`, which does not parse.
        sigemptyset(&empty);
        ::sigprocmask(SIG_SETMASK, &empty, nullptr);

        if (compiled.new_process_group) ::setpgid(0, 0);

        // chdir BEFORE the sandbox: the profile may not grant traversal to the
        // workdir's ancestors, and chdir after entering would then fail for a
        // directory the guest is allowed to be in.
        if (workdir != nullptr && ::chdir(workdir) != 0) {
            safe_write(2, "claybin: chdir failed\n");
            ::_exit(kExitPlanFailed);
        }

        // rlimits before the sandbox, because setrlimit itself may be denied
        // by the profile.
        for (const auto& rl : compiled.rlimits) {
            struct rlimit lim {};
            if (::getrlimit(rl.resource, &lim) == 0) {
                // never RAISE a limit: the policy is a ceiling, and a sandbox
                // that hands the guest more than the caller's own process had
                // is a privilege escalation wearing a resource-limit costume.
                const rlim_t want = static_cast<rlim_t>(rl.value);
                if (lim.rlim_max == RLIM_INFINITY || want < lim.rlim_max) {
                    lim.rlim_cur = want;
                    lim.rlim_max = want;
                } else {
                    lim.rlim_cur = lim.rlim_max;
                }
                if (::setrlimit(rl.resource, &lim) != 0) {
                    safe_write(2, "claybin: setrlimit failed\n");
                    ::_exit(kExitPlanFailed);
                }
            }
        }

        // ---- descriptors, BEFORE the sandbox ----
        //
        // ordering that looks backwards and is not. doing this after
        // sandbox_init needs the profile to permit open("/dev/null") and
        // dup2, so a caller who turned prerequisites off would find their
        // redirects silently failing. worse, it puts the setup window on the
        // WRONG side of the wall: the kernel writes its own rejection message
        // to stderr when a profile is refused, and if stderr has not been
        // redirected yet that message lands on the caller's terminal instead
        // of in the pipe the caller supplied for exactly this purpose.
        //
        // the fds themselves are authority, but they are authority the CALLER
        // chose to hand over -- same contract as Command::FdMap on linux --
        // so installing them before the wall goes up grants nothing new.
        auto redirect = [](int want, int target) {
            if (want == SpawnRequest::kDevNull) {
                const int nul = ::open("/dev/null", O_RDWR);
                if (nul < 0) return false;
                if (::dup2(nul, target) < 0) return false;
                if (nul != target) ::close(nul);
                return true;
            }
            if (want < 0) return true;  // inherit
            return ::dup2(want, target) >= 0;
        };
        if (!redirect(req.stdin_fd, 0) || !redirect(req.stdout_fd, 1) ||
            !redirect(req.stderr_fd, 2)) {
            safe_write(2, "claybin: fd setup failed\n");
            ::_exit(kExitPlanFailed);
        }

        for (int i = 0; i < req.fd_count && i < SpawnRequest::kMaxFdMaps; ++i) {
            const auto& m = req.fds[i];
            if (m.parent_fd < 0 || m.child_fd < 0) continue;
            if (m.parent_fd != m.child_fd && ::dup2(m.parent_fd, m.child_fd) < 0) {
                safe_write(2, "claybin: fd map failed\n");
                ::_exit(kExitPlanFailed);
            }
            // clear CLOEXEC on the landing slot: the caller asked for this fd
            // to survive exec. dup2 already clears it on the new descriptor,
            // but the explicit call documents the intent and covers the
            // parent_fd == child_fd case, where no dup2 happened at all.
            ::fcntl(m.child_fd, F_SETFD, 0);
        }

        // ---- enter the sandbox ----
        //
        // this is the point of no return: seatbelt profiles are irreversible
        // and survive exec, which is the property that makes them worth using.
        // if it fails we MUST NOT continue -- a child that survived a failed
        // sandbox setup is unconfined, and running the target program in it
        // would be the exact failure mode this library exists to prevent.
        if (profile != nullptr) {
            char* err = nullptr;
            if (::sandbox_init(profile, 0, &err) != 0) {
                safe_write(2, "claybin: sandbox_init failed: ");
                if (err != nullptr) safe_write(2, err);
                safe_write(2, "\n");
                ::_exit(kExitPlanFailed);
            }
        }

        ::execve(req.program, const_cast<char* const*>(req.argv),
                 req.envp != nullptr ? const_cast<char* const*>(req.envp) : claybin_environ);
        safe_write(2, "claybin: execve failed\n");
        ::_exit(kExitExecFailed);
    }

    // ================= PARENT ==========================================
    //
    // set the child's process group here too. setpgid is racy by design --
    // whichever side wins, the group is set before the parent can signal it,
    // and the loser gets EACCES/ESRCH, both harmless.
    if (compiled.new_process_group) ::setpgid(pid, pid);

    return Spawned{pid};
}

#endif  // __APPLE__

}  // namespace clay::macos
