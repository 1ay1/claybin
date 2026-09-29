// claybin: ready-made syscall profiles.
//
// hand-writing an allow-list is how people get this wrong: miss one syscall the
// libc startup path needs and the child dies before main(), usually with a
// confusing SIGSYS. these profiles are the tested baselines to build on.
//
// x86_64 numbers. other arches get their own table; the policy layer is
// arch-independent, only these constants are not.
#pragma once

#include "claybin/policy/syscalls.hpp"

namespace clay::profiles {

#if defined(__x86_64__)

// the bare minimum for a dynamically linked program to start, run, and exit.
// anything that cannot be justified as "libc needs this before main" belongs in
// a more specific profile, not here.
//
// NOTE: there is deliberately no execve here. that means a policy using bare
// base() cannot be handed to spawn(), because spawn's own execve would be the
// first thing the filter denies -- you get EPERM from execve and it looks like
// the sandbox is broken. use with_processes() or compiler() when the sandboxed
// program is launched by exec, which is almost always. base() is for a process
// that sandboxes ITSELF after it is already running.
inline SyscallPolicy base() {
    SyscallPolicy p;
    p.set_default(SysAction::errno_, 1 /* EPERM */);

    static constexpr SysNr kAllowed[] = {
        0,    // read
        1,    // write
        3,    // close
        5,    // fstat
        8,    // lseek
        9,    // mmap
        10,   // mprotect
        11,   // munmap
        12,   // brk
        13,   // rt_sigaction
        14,   // rt_sigprocmask
        15,   // rt_sigreturn
        16,   // ioctl  (isatty; narrowed by landlock's ioctl_dev on abi>=5)
        17,   // pread64
        18,   // pwrite64
        19,   // readv
        20,   // writev
        24,   // sched_yield
        28,   // madvise
        39,   // getpid
        60,   // exit
        63,   // uname
        72,   // fcntl
        79,   // getcwd
        89,   // readlink
        96,   // gettimeofday
        97,   // getrlimit
        98,   // getrusage
        102,  // getuid
        104,  // getgid
        107,  // geteuid
        108,  // getegid
        110,  // getppid
        158,  // arch_prctl
        186,  // gettid
        201,  // time
        202,  // futex
        204,  // sched_getaffinity
        218,  // set_tid_address
        228,  // clock_gettime
        230,  // clock_nanosleep
        231,  // exit_group
        234,  // tgkill    (abort/assert)
        257,  // openat
        262,  // newfstatat
        273,  // set_robust_list
        302,  // prlimit64
        318,  // getrandom
        334,  // rseq
    };
    p.allow(std::span<const SysNr>{kAllowed});

    // clone3 is deliberately NOT allowed, and the errno is ENOSYS rather than
    // EPERM on purpose.
    //
    // clone3 takes a POINTER to struct clone_args, so its flags live in memory
    // and seccomp cannot see them -- and filtering them by dereferencing the
    // pointer is unsound, because the guest can rewrite it between the check and
    // the syscall. that makes clone3 a hole straight through the clone flag
    // rules below: deny unshare and mask off CLONE_NEWUSER on clone, and
    // clone3(CLONE_NEWUSER) still gets you a namespace.
    //
    // ENOSYS is what makes this safe rather than merely strict: glibc probes
    // clone3 and falls back to clone when the kernel says "no such syscall",
    // which is exactly the path we can filter. EPERM here would make
    // pthread_create fail instead of fall back.
    p.deny(435 /* clone3 */, 38 /* ENOSYS */);

    // process-group and session calls. these are NOT privileges -- they only
    // touch the caller's own group -- but every shell calls them during startup
    // and a missing one produces the baffling
    // "initialize_job_control: getpgrp failed: Success", which cost an
    // afternoon the first time. a sandbox that cannot run /bin/sh is not much
    // of a sandbox.
    static constexpr SysNr kJobControl[] = {
        39,   // getpid (already above, harmless to repeat)
        109,  // setpgid
        110,  // getppid
        111,  // getpgrp
        112,  // setsid
        121,  // getpgid
        122,  // getsid
        124,  // getsid variant on some ABIs
        14,   // rt_sigprocmask (already above)
        13,   // rt_sigaction (already above)
    };
    p.allow(std::span<const SysNr>{kJobControl});

    // the modern variants glibc actually calls. the older numbers are not
    // enough on their own: libc prefers pipe2/dup3/openat and only falls back
    // to pipe/dup2/open on ancient kernels, so a list with just the classic
    // numbers produces "pipe error: Operation not permitted" from any shell
    // running a pipeline.
    static constexpr SysNr kModern[] = {
        22,   // pipe
        32,   // dup
        33,   // dup2
        292,  // dup3
        293,  // pipe2
        213,  // epoll_create
        291,  // epoll_create1
        232,  // epoll_wait
        281,  // epoll_pwait
        233,  // epoll_ctl
        23,   // select
        7,    // poll
        271,  // ppoll
        270,  // pselect6
        302,  // prlimit64
        99,   // sysinfo
        137,  // statfs
        138,  // fstatfs
    };
    p.allow(std::span<const SysNr>{kModern});

    // explicitly kill rather than errno for the classic escape attempts. a
    // denied-with-EPERM ptrace looks like a permissions hiccup; a killed one is
    // an unmistakable signal in an audit log.
    for (SysNr nr : {101u /* ptrace */, 165u /* mount */, 166u /* umount2 */,
                     155u /* pivot_root */, 161u /* chroot */, 272u /* unshare */,
                     308u /* setns */, 321u /* bpf */, 298u /* perf_event_open */,
                     175u /* init_module */, 176u /* delete_module */,
                     246u /* kexec_load */, 169u /* reboot */})
        p.kill(nr);

    // ---- dangerous ioctls, denied by ARGUMENT ----------------------------
    //
    // ioctl has to stay allowed: isatty() calls it, and so does every program
    // that checks whether stdout is a terminal. but a handful of requests are
    // outright escapes, and without argument filtering the only choices were
    // "allow the escape" or "break isatty for everyone".
    //
    // TIOCSTI is the important one. it pushes a byte into a terminal's input
    // queue -- so a guest sharing a controlling terminal with an interactive
    // shell can TYPE INTO THAT SHELL, and whatever it types runs outside the
    // sandbox. modern kernels gate it behind dev.tty.legacy_tiocsti, but a
    // sandbox that relies on a host sysctl is not a sandbox, so we deny it
    // ourselves. new_session() also fixes this; defence in depth means doing
    // both, since a caller may reasonably want to keep the tty.
    //
    // TIOCLINUX can do the same thing via its subcommand 2 (TIOCL_SETSEL),
    // and TIOCCONS redirects console output.
    static constexpr std::uint64_t kTiocsti = 0x5412;
    static constexpr std::uint64_t kTioclinux = 0x541C;
    static constexpr std::uint64_t kTioccons = 0x541D;
    static constexpr std::uint64_t kTiocsctty = 0x540E;
    for (std::uint64_t req : {kTiocsti, kTioclinux, kTioccons, kTiocsctty})
        p.deny_arg(16 /* ioctl */, 1 /* request */, req, SysAction::errno_, 1 /* EPERM */);

    // W^X: no mapping may be writable and executable at the same time.
    //
    // this does not stop a determined attacker -- they can mmap writable, write
    // their code, then mprotect it executable -- but it does break the whole
    // class of exploits that rely on a single RWX mapping, and it costs nothing
    // for ordinary programs, which never ask for one. JITs do, which is why this
    // lives here and not in a profile a JIT would use.
    //
    // not_all is the right comparison: PROT_WRITE|PROT_EXEC is forbidden as a
    // COMBINATION, while either alone is fine. an equality test on the pair
    // would miss PROT_READ|PROT_WRITE|PROT_EXEC, which is what a real exploit
    // actually asks for.
    static constexpr std::uint64_t kProtWriteExec = 0x2 | 0x4;
    p.deny_arg_all(9 /* mmap */, 2 /* prot */, kProtWriteExec, SysAction::errno_, 1);
    p.deny_arg_all(10 /* mprotect */, 2 /* prot */, kProtWriteExec, SysAction::errno_, 1);

    return p;
}

// every CLONE_NEW* flag. a new namespace of any kind is the first move in most
// container escapes: a user namespace hands back capabilities, a mount namespace
// is a step towards remounting something writable, and a pid namespace hides
// processes from a supervisor watching from outside.
//
// masking these off clone is what makes threads work while namespaces do not --
// pthread_create sets CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD,
// none of which are here.
//
// these values are from linux/sched.h and are NOT guessable. CLONE_VM is
// 0x00000100 and CLONE_NEWNS is 0x00020000; getting that pair backwards puts
// CLONE_VM in this mask and denies every pthread_create in the sandbox.
inline constexpr std::uint64_t kCloneNewNamespaces =
    0x00020000ull |  // CLONE_NEWNS      -- mount
    0x02000000ull |  // CLONE_NEWCGROUP
    0x04000000ull |  // CLONE_NEWUTS     -- hostname
    0x08000000ull |  // CLONE_NEWIPC
    0x10000000ull |  // CLONE_NEWUSER    -- the dangerous one
    0x20000000ull |  // CLONE_NEWPID
    0x40000000ull;   // CLONE_NEWNET
                     // 0x80000000 is CLONE_IO, not a namespace. leave it alone.

// grant subprocesses and threads on top of an existing profile, WITH the clone
// flag mask that makes it safe.
//
// this is a mutating helper rather than a composition because composition of
// sealed authority is meet -- intersection -- and intersecting two profiles
// would deny everything either one denies, which is the opposite of "add exec
// to a filesystem profile". granting is only ever explicit, so it looks like a
// function call that takes a policy apart and puts more in.
inline SyscallPolicy& add_processes(SyscallPolicy& p) {
    for (SysNr nr : {56u /* clone */, 57u /* fork */, 58u /* vfork */, 59u /* execve */,
                     61u /* wait4 */, 62u /* kill */, 322u /* execveat */})
        p.allow(nr);

    // clone is allowed, but not for making namespaces. base() already denies
    // unshare and clone3 outright; this closes the third door.
    //
    // any_set, not equality: the guest picks the other flags, so the only sound
    // question is "is any namespace bit present".
    p.deny_arg_any(56 /* clone */, 0 /* flags */, kCloneNewNamespaces, SysAction::errno_,
                   1 /* EPERM */);
    return p;
}

// base plus threads and subprocesses. this is the smallest profile that works
// with spawn(), because it is the first one that allows execve.
inline SyscallPolicy with_processes() {
    SyscallPolicy p = base();
    add_processes(p);
    return p;
}

// base plus the filesystem calls a compiler or build tool needs.
//
// like base(), this has no execve: it is for a process restricting itself. if
// you are going to spawn() into it, use compiler() instead.
inline SyscallPolicy with_filesystem() {
    SyscallPolicy p = base();
    for (SysNr nr : {2u /* open */, 4u /* stat */, 6u /* lstat */, 21u /* access */,
                     22u /* pipe */, 32u /* dup */, 33u /* dup2 */, 77u /* ftruncate */,
                     78u /* getdents */, 82u /* rename */, 83u /* mkdir */, 84u /* rmdir */,
                     87u /* unlink */, 88u /* symlink */, 90u /* chmod */, 91u /* fchmod */,
                     133u /* mknod */, 217u /* getdents64 */, 260u /* fchownat */,
                     263u /* unlinkat */, 264u /* renameat */, 265u /* linkat */,
                     266u /* symlinkat */, 269u /* faccessat */, 280u /* utimensat */,
                     285u /* fallocate */, 316u /* renameat2 */, 332u /* statx */,
                     439u /* faccessat2 */})
        p.allow(nr);
    return p;
}

// a build/compile sandbox: files plus subprocesses, no network.
inline SyscallPolicy compiler() {
    SyscallPolicy p = with_filesystem();
    add_processes(p);
    return p;
}

// base plus TCP client sockets.
//
// pair this with a per-port `connect()` grant: landlock (abi 4+) then mediates
// which ports are reachable, so "this program may talk to exactly 443" is
// enforced by the kernel rather than merely described. seccomp alone can only
// say "sockets yes or no" -- the port granularity comes from landlock, and the
// two together are what a netns cannot give you.
//
// like with_filesystem(), this has NO execve: it is for a process restricting
// itself. use compiler_with_network() when spawn() has to exec into it.
inline SyscallPolicy with_network() {
    SyscallPolicy p = with_filesystem();
    for (SysNr nr : {41u /* socket */, 42u /* connect */, 43u /* accept */,
                     44u /* sendto */, 45u /* recvfrom */, 46u /* sendmsg */,
                     47u /* recvmsg */, 48u /* shutdown */, 49u /* bind */,
                     50u /* listen */, 51u /* getsockname */, 52u /* getpeername */,
                     54u /* setsockopt */, 55u /* getsockopt */, 288u /* accept4 */,
                     299u /* recvmmsg */, 307u /* sendmmsg */})
        p.allow(nr);
    return p;
}

// the shape an agent-run build wants: files, subprocesses, and brokered network.
inline SyscallPolicy compiler_with_network() {
    SyscallPolicy p = with_network();
    add_processes(p);
    return p;
}

#else

// the profiles are syscall-number tables, so they are arch-specific by nature.
// refuse rather than hand back a table for the wrong architecture.
inline SyscallPolicy base() { return SyscallPolicy::nothing(); }
inline SyscallPolicy with_processes() { return SyscallPolicy::nothing(); }
inline SyscallPolicy with_filesystem() { return SyscallPolicy::nothing(); }
inline SyscallPolicy compiler() { return SyscallPolicy::nothing(); }
inline SyscallPolicy with_network() { return SyscallPolicy::nothing(); }
inline SyscallPolicy compiler_with_network() { return SyscallPolicy::nothing(); }

#endif

}  // namespace clay::profiles
