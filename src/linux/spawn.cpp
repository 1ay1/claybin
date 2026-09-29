#include "claybin/plan/spawn.hpp"

#if defined(__linux__)

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

namespace clay {

Result<Spawned> spawn(const Plan& plan, const Command& cmd) {
    return spawn_in(plan, cmd, cgroup::Group{});
}

Result<Spawned> spawn_in(const Plan& plan, const Command& cmd, const cgroup::Group& cg) {
    if (!cmd.program || !cmd.argv)
        return std::unexpected(Error{Errc::invalid_policy, "spawn: no program"});
    if (!plan.well_ordered())
        return std::unexpected(Error{Errc::invalid_policy, "spawn: plan not well ordered"});

    // does this plan broker syscalls? if so the listener fd has to make a
    // three-hop journey (guest -> shepherd -> supervisor) for reasons the
    // shepherd branch explains, and that needs an extra pipe.
    bool brokering = false;
    plan.for_each([&](OpCode code, std::span<const std::byte> pl) {
        if (code == OpCode::seccomp_install) {
            SeccompInstallOp o{};
            if (Plan::decode(pl, o) && (o.flags & 1u)) brokering = true;
            return false;
        }
        return true;
    });

    int relay[2] = {-1, -1};
    if (brokering && ::pipe2(relay, O_CLOEXEC) < 0)
        return std::unexpected(Error{Errc::spawn_failed, "pipe2 relay", errno});

    // a CLOEXEC socketpair, not a pipe: the child may need to send the seccomp
    // listener fd back, and SCM_RIGHTS needs a socket. on a successful exec the
    // write end closes and the parent reads EOF, exactly as with a pipe.
    int report[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, report) < 0)
        return std::unexpected(Error{Errc::spawn_failed, "socketpair", errno});

    // a second pipe, the other direction: the child blocks on it until the
    // parent has put it in the cgroup. without this gate the child could exec
    // and start allocating before its memory limit exists, which would make the
    // limit advisory rather than enforced.
    int gate[2] = {-1, -1};
    const bool use_cgroup = cg.valid();
    if (use_cgroup && ::pipe2(gate, O_CLOEXEC) < 0) {
        ::close(report[0]);
        ::close(report[1]);
        return std::unexpected(Error{Errc::spawn_failed, "pipe2 gate", errno});
    }

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
            if (use_cgroup) {
                ::close(gate[0]);
                ::close(gate[1]);
            }
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
        if (use_cgroup) ::close(gate[1]);

        // tell the plan which fds to spare when it closes inherited descriptors.
        // without this the close takes our own failure channel with it, and every
        // later error reaches the parent as a bare exit code.
        Plan::set_report_fd(report[1]);
        // and the broker relay, which the guest writes its listener fd number to
        // AFTER the privdrop phase that does the closing.
        if (brokering) Plan::set_relay_fd(relay[1]);

        struct Failure {
            int stage;  // 0 = plan, 1 = exec
            int code;
            int sys_errno;
            char mech[32];
        } f{};

        // wait for the parent to put us in our cgroup. a single byte, or EOF if
        // the parent gave up. this must happen BEFORE any of the sandbox setup
        // that allocates, so the memory cap covers everything we do.
        if (use_cgroup) {
            char go = 0;
            ssize_t got = ::read(gate[0], &go, 1);
            ::close(gate[0]);
            if (got != 1) ::_exit(kExitPlanFailed);
        }

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
                // the outer child is the shepherd: it holds pid 1 of the new pid
                // namespace and mirrors the guest's exit status.
                //
                // it is ALSO the only process that can hand the seccomp listener
                // to the supervisor. the guest cannot: SCM_RIGHTS refuses a
                // notify fd once no_new_privs is set, and the guest's own pid is
                // 1 in its namespace, so the supervisor cannot name it for
                // pidfd_getfd either.
                //
                // the shepherd can, because it is the guest's PARENT and is
                // OUTSIDE the seccomp filter: pidfd_open on its own child, then
                // pidfd_getfd, then SCM_RIGHTS to the supervisor -- which works
                // because the shepherd never set no_new_privs on itself.
                // the shepherd's job for brokering: tell the SUPERVISOR which
                // pid holds the listener and which fd number it is. it cannot
                // pass the descriptor itself -- the kernel refuses SCM_RIGHTS on
                // a seccomp notify fd whose owner has no_new_privs set, whoever
                // is doing the sending -- but pidfd_getfd from the supervisor is
                // allowed, because that is gated on PTRACE_MODE_ATTACH rather
                // than on moving a filter-bypass capability across a boundary.
                //
                // the shepherd is the one that knows the guest's HOST pid: inside
                // the new pid namespace the guest sees itself as 1, which is
                // useless to anyone outside.
                if (brokering) {
                    struct Handshake {
                        int stage, code, sys_errno;
                        char mech[32];
                    } hs{};
                    if (::read(relay[0], &hs, sizeof hs) == static_cast<ssize_t>(sizeof hs) &&
                        hs.stage == 2) {
                        // rewrite the pid to the one the SUPERVISOR can name, and
                        // forward it on the report socket.
                        hs.sys_errno = static_cast<int>(inner);
                        ssize_t w2 = ::write(report[1], &hs, sizeof hs);
                        (void)w2;
                    }
                }
                ::close(report[1]);
                int wst = 0;
                ::waitpid(inner, &wst, 0);
                if (WIFSIGNALED(wst)) ::_exit(128 + WTERMSIG(wst));
                ::_exit(WIFEXITED(wst) ? WEXITSTATUS(wst) : 1);
            }
            // grandchild: finish the plan.
            //
            // NOTE ON BROKERING. the seccomp listener fd cannot be handed to the
            // supervisor with SCM_RIGHTS. once no_new_privs is set -- which it
            // must be, before both landlock and seccomp -- the kernel refuses to
            // pass a notify fd over a unix socket, because that would let an
            // unprivileged process give another process the ability to answer
            // (and therefore bypass) its filter. sendmsg returns EPERM, and no
            // amount of reordering helps: the fd does not exist until seccomp is
            // installed, and seccomp cannot be installed before nnp.
            //
            // so the supervisor fetches it the other way round, with
            // pidfd_getfd(), which is the interface the kernel provides for
            // exactly this and which requires PTRACE_MODE_ATTACH on the target --
            // i.e. the supervisor's existing authority over its own child, rather
            // than a new capability crossing a boundary. spawn() therefore
            // reports the fd NUMBER, and the parent pulls the descriptor across.
            st = plan.apply_from(Phase::mounts);

            // report the listener fd NUMBER so the parent can fetch it with
            // pidfd_getfd. the descriptor itself cannot cross the boundary (see
            // the note above), but its number is just an integer.
            if (st) {
                int nfd = Plan::take_notify_fd();
                if (nfd >= 0) {
                    struct Handshake {
                        int stage;
                        int code;
                        int sys_errno;
                        char mech[32];
                    } hs{};
                    hs.stage = 2;  // 2 = broker handshake, not a failure
                    hs.code = nfd;
                    // our own pid, so the parent can open a pidfd on US rather
                    // than on the shepherd -- the listener lives in this process.
                    hs.sys_errno = static_cast<int>(::getpid());
                    ssize_t w = ::write(relay[1], &hs, sizeof hs);
                    (void)w;
                    // do NOT close nfd: the parent needs it to still exist in our
                    // descriptor table when it calls pidfd_getfd, and it stays
                    // valid across the exec because the kernel keeps the listener
                    // alive as long as the filter is.
                }
            }
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
    if (brokering) {
        ::close(relay[0]);
        ::close(relay[1]);
    }

    // put the child in its cgroup, then release it. doing this here rather than
    // in the child is what keeps the post-fork path free of sysfs work.
    if (use_cgroup) {
        ::close(gate[0]);
        auto att = cg.attach(static_cast<int>(pid));
        if (!att) {
            // could not enforce the limits we promised. kill the child rather
            // than run it unlimited: it has not exec'd yet, so nothing of the
            // caller's program has run.
            ::close(gate[1]);
            ::kill(static_cast<pid_t>(pid), SIGKILL);
            int st = 0;
            ::waitpid(static_cast<pid_t>(pid), &st, 0);
            ::close(report[0]);
            if (pidfd >= 0) ::close(pidfd);
            return std::unexpected(att.error());
        }
        char go = 1;
        ssize_t w = ::write(gate[1], &go, 1);
        (void)w;
        ::close(gate[1]);
    }

    struct Failure {
        int stage, code, sys_errno;
        char mech[32];
    } f{};

    // recvmsg, because the shepherd may relay the seccomp listener as ancillary
    // data. a plain failure report arrives the same way.
    int received_fd = -1;
    ssize_t n;
    {
        struct iovec iov{};
        iov.iov_base = &f;
        iov.iov_len = sizeof f;
        union {
            char buf[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } u{};
        struct msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = u.buf;
        msg.msg_controllen = sizeof u.buf;
        n = ::recvmsg(report[0], &msg, 0);
        if (n > 0)
            for (struct cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm))
                if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS)
                    std::memcpy(&received_fd, CMSG_DATA(cm), sizeof received_fd);
    }
    ::close(report[0]);

    // a stage-2 message is the broker handshake: the shepherd told us which host
    // pid holds the listener and at which fd number. we fetch the descriptor
    // ourselves with pidfd_getfd, which the kernel permits because it is gated on
    // the authority we already have over our own descendants.
    if (n == static_cast<ssize_t>(sizeof f) && f.stage == 2) {
        int listener = -1;
        long gp = ::syscall(SYS_pidfd_open, f.sys_errno, 0);
        if (gp >= 0) {
            long got = ::syscall(SYS_pidfd_getfd, static_cast<int>(gp), f.code, 0);
            if (got >= 0) listener = static_cast<int>(got);
            ::close(static_cast<int>(gp));
        }
        if (listener < 0) {
            int err = errno;
            ::kill(static_cast<pid_t>(pid), SIGKILL);
            int st2 = 0;
            ::waitpid(static_cast<pid_t>(pid), &st2, 0);
            if (pidfd >= 0) ::close(pidfd);
            return std::unexpected(Error{Errc::io_error, "broker: pidfd_getfd", err});
        }
        return Spawned{static_cast<int>(pid), pidfd, listener};
    }

    if (received_fd >= 0 && n == 1) return Spawned{static_cast<int>(pid), pidfd, received_fd};

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

    return Spawned{static_cast<int>(pid), pidfd, -1};
}

}  // namespace clay

#else

namespace clay {
Result<Spawned> spawn(const Plan&, const Command&) {
    return std::unexpected(Error{Errc::unsupported, "spawn: linux only"});
}
}  // namespace clay

#endif
