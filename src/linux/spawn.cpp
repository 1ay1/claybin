#include "claybin/plan/spawn.hpp"

#if defined(__linux__)

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace clay {

Result<Spawned> spawn(const Plan& plan, const Command& cmd) {
    if (!cmd.program || !cmd.argv)
        return std::unexpected(Error{Errc::invalid_policy, "spawn: no program"});
    if (!plan.well_ordered())
        return std::unexpected(Error{Errc::invalid_policy, "spawn: plan not well ordered"});

    // a CLOEXEC pipe is the standard way for a child to report why it could not
    // start: on a successful exec the write end closes and the parent reads
    // EOF. anything else means setup failed, and we get the real reason instead
    // of a bare exit code.
    int report[2] = {-1, -1};
    if (::pipe2(report, O_CLOEXEC) < 0)
        return std::unexpected(Error{Errc::spawn_failed, "pipe2", errno});

    // CLONE_PIDFD gives us a race-free handle on the child. without it, a pid
    // can be reused between exit and wait, and we would be signalling a
    // stranger. fall back only if the kernel refuses.
    int pidfd = -1;
    struct clone_args {
        std::uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
        std::uint64_t set_tid, set_tid_size, cgroup;
    } args{};
    args.flags = 0x00001000ull;  // CLONE_PIDFD
    args.pidfd = reinterpret_cast<std::uint64_t>(&pidfd);
    args.exit_signal = SIGCHLD;

    long pid = ::syscall(SYS_clone3, &args, sizeof args);
    if (pid < 0) {
        pidfd = -1;
        pid = ::fork();
        if (pid < 0) {
            ::close(report[0]);
            ::close(report[1]);
            return std::unexpected(Error{Errc::spawn_failed, "fork", errno});
        }
    }

    if (pid == 0) {
        // ---- child. from here on: no allocation, no stdio, no returning. ----
        //
        // every path out of this block is an _exit(). returning would unwind
        // into the caller's stack frame with a half-built sandbox in place,
        // which is the one outcome worse than failing to start.
        ::close(report[0]);

        struct Failure {
            int stage;  // 0 = plan, 1 = exec
            int code;
            int sys_errno;
            char mech[32];
        } f{};

        // the pid namespace needs a fork to ENTER: unshare(CLONE_NEWPID) puts
        // our children inside it and leaves us outside, and mounting procfs
        // requires membership. the plan's own unshare op already created the
        // namespace (along with user/mount/net), so here we only need to step
        // into it before the mount phase runs.
        //
        // apply_until() runs the namespace phase, we fork, then the grandchild
        // runs the rest -- mounts included -- as a real member of the new pid
        // namespace, and as its pid 1.
        auto st = plan.apply_until(Phase::mounts);
        if (st) {
            pid_t inner = ::fork();
            if (inner < 0) {
                f.stage = 0;
                f.sys_errno = errno;
                for (int k = 0; k < 8; ++k) f.mech[k] = "pid-fork"[k];
                ssize_t ig = ::write(report[1], &f, sizeof f);
                (void)ig;
                ::_exit(kExitPlanFailed);
            }
            if (inner > 0) {
                // the outer child is only a shepherd: it waits for the real
                // sandboxed process and mirrors its exit status, so the
                // caller's waitpid() still means what they expect.
                ::close(report[1]);
                int wst = 0;
                ::waitpid(inner, &wst, 0);
                if (WIFSIGNALED(wst)) ::_exit(128 + WTERMSIG(wst));
                ::_exit(WIFEXITED(wst) ? WEXITSTATUS(wst) : 1);
            }
            // grandchild: finish the plan from the mount phase on
            st = plan.apply_from(Phase::mounts);
        }

        if (!st) {
            f.stage = 0;
            f.code = static_cast<int>(st.error().code);
            f.sys_errno = st.error().sys_errno;
            auto m = st.error().mechanism;
            std::size_t n = m.size() < sizeof(f.mech) - 1 ? m.size() : sizeof(f.mech) - 1;
            for (std::size_t i = 0; i < n; ++i) f.mech[i] = m[i];
            ssize_t ignored = ::write(report[1], &f, sizeof f);
            (void)ignored;
            ::_exit(kExitPlanFailed);
        }

        ::execve(cmd.program, const_cast<char* const*>(cmd.argv),
                 const_cast<char* const*>(cmd.envp ? cmd.envp : environ));

        f.stage = 1;
        f.sys_errno = errno;
        ssize_t ignored = ::write(report[1], &f, sizeof f);
        (void)ignored;
        ::_exit(kExitExecFailed);
    }

    // ---- parent ----
    ::close(report[1]);
    struct Failure {
        int stage, code, sys_errno;
        char mech[32];
    } f{};
    ssize_t n = ::read(report[0], &f, sizeof f);
    ::close(report[0]);

    if (n == static_cast<ssize_t>(sizeof f)) {
        // the child told us why. reap it so we do not leave a zombie, then
        // report the real reason rather than a generic spawn failure.
        int status = 0;
        ::waitpid(static_cast<pid_t>(pid), &status, 0);
        if (pidfd >= 0) ::close(pidfd);
        f.mech[sizeof(f.mech) - 1] = '\0';
        static thread_local char mech_copy[32];
        for (std::size_t i = 0; i < sizeof mech_copy; ++i) mech_copy[i] = f.mech[i];
        return std::unexpected(Error{f.stage == 0 ? static_cast<Errc>(f.code) : Errc::spawn_failed,
                                     f.stage == 0 ? mech_copy : "execve", f.sys_errno});
    }

    return Spawned{static_cast<int>(pid), pidfd};
}

}  // namespace clay

#else

namespace clay {
Result<Spawned> spawn(const Plan&, const Command&) {
    return std::unexpected(Error{Errc::unsupported, "spawn: linux only"});
}
}  // namespace clay

#endif
