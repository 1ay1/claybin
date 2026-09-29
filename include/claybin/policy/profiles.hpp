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

// the namespace is overridable for the same reason the arch is: a test that
// wants both tables in one binary needs them to be DIFFERENT symbols. these are
// inline functions, so two translation units defining `clay::profiles::base()`
// differently is an ODR violation the linker resolves by silently picking one --
// which is not a diagnostic, it is a wrong answer.
#if !defined(CLAY_PROFILES_NAMESPACE)
#define CLAY_PROFILES_NAMESPACE profiles
#endif

namespace clay::CLAY_PROFILES_NAMESPACE {

// which arch's syscall table to compile. normally the one we are building for,
// but overridable so the tables can be TESTED on a different host: an untested
// syscall table is a list of guesses, and cross-compiling the whole library
// just to check 130 numbers is a poor trade.
//
// CLAY_PROFILE_ARCH_AARCH64 selects the aarch64 block regardless of host. it
// only changes which numbers the tables contain -- it cannot make a filter for
// the wrong arch get INSTALLED, because bpf::compile() guards on the real
// audit arch from native_arch() and that is not overridable.
#if defined(CLAY_PROFILE_ARCH_AARCH64)
#define CLAY_PROFILES_AARCH64 1
#elif defined(CLAY_PROFILE_ARCH_X86_64)
#define CLAY_PROFILES_X86_64 1
#elif defined(__x86_64__)
#define CLAY_PROFILES_X86_64 1
#elif defined(__aarch64__)
#define CLAY_PROFILES_AARCH64 1
#endif

#if defined(CLAY_PROFILES_X86_64)

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
        124,  // getsid
        // NOT 122 or 123. those are setfsuid and setfsgid, and 122 was in this
        // list labelled "getsid" -- which is 124. a mislabelled number in an
        // allow-list is the worst kind of typo: nothing breaks to tell you it is
        // there, and reading the list does not catch it, twice.
        //
        // being straight about the severity: setfsuid needs CAP_SETUID, and the
        // sandbox drops the whole bounding set before seccomp, so this was not
        // exploitable -- measured, the fsuid does not budge inside claybin.
        // it was defence-in-depth that had quietly stopped being defence. the
        // real fix is not this line, it is syscall_table_test, which resolves
        // every name through the kernel's own headers so the next mislabelled
        // number fails a test instead of sitting here.
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

    // ---- ioctl, restricted by ARGUMENT to an allow-list -------------------
    //
    // ioctl has to stay allowed: isatty() calls it, and so does every program
    // that checks whether stdout is a terminal. but it is the widest syscall in
    // the kernel -- thousands of requests, and any loaded driver adds more -- so
    // a deny-list is a list of the escapes somebody already thought of. this is
    // an allow-list instead: everything is EPERM except the requests a normal
    // program genuinely needs.
    //
    // that closes the ones a deny-list would have to name one at a time, most
    // importantly TIOCSTI. TIOCSTI pushes a byte into a terminal's input queue,
    // so a guest sharing a controlling terminal with an interactive shell can
    // TYPE INTO THAT SHELL and have it run outside the sandbox. modern kernels
    // gate it behind dev.tty.legacy_tiocsti, but a sandbox that relies on a host
    // sysctl is not a sandbox. TIOCLINUX does the same thing via its subcommand
    // TIOCL_SETSEL, TIOCCONS redirects console output, and TIOCSCTTY steals a
    // controlling terminal -- none of which are on this list, so none need
    // naming.
    //
    // these are 32-BIT comparisons. ioctl's cmd is `unsigned int` and the kernel
    // truncates the register before using it, so a rule that also requires the
    // high half to be zero is bypassed by ioctl(fd, 0xdeadbeef00005412), which
    // runs as TIOCSTI. that is measured, not theoretical.
    //
    // values from asm-generic/ioctls.h.
    static constexpr std::uint32_t kIoctlAllowed[] = {
        // terminal attributes. isatty() is TCGETS, and every shell and libc
        // startup path touches these.
        0x5401,  // TCGETS
        0x5402,  // TCSETS
        0x5403,  // TCSETSW
        0x5404,  // TCSETSF
        0x5405,  // TCGETA
        0x5409,  // TCSBRK
        0x540A,  // TCXONC
        0x540B,  // TCFLSH
        // window size. anything that formats output for a terminal asks.
        0x5413,  // TIOCGWINSZ
        0x5414,  // TIOCSWINSZ
        // process group and session. job control, and read-only queries.
        0x540F,  // TIOCGPGRP
        0x5410,  // TIOCSPGRP
        0x5429,  // TIOCGSID
        // descriptor state. these act on the fd, not on any device.
        0x541B,  // FIONREAD
        0x5421,  // FIONBIO
        0x5450,  // FIONCLEX
        0x5451,  // FIOCLEX
        0x5411,  // TIOCOUTQ
    };
    p.allow_arg32_only(16 /* ioctl */, 1 /* request */,
                       std::span<const std::uint32_t>{kIoctlAllowed}, SysAction::errno_,
                       1 /* EPERM */);

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

#elif defined(CLAY_PROFILES_AARCH64)

// ---------------------------------------------------------------------------
// aarch64.
//
// a second table rather than a mapping layer, because a syscall number IS the
// arch-specific thing -- there is no portable name a filter can act on, and a
// translation table would just be this list with an extra chance to be wrong.
//
// every number here came out of <asm-generic/unistd.h>, which is the table
// aarch64 uses. NOT from memory: the x86_64 list above shipped with 122
// labelled "getsid" (it is setfsuid, getsid is 124), which is exactly the
// mistake a hand-written table invites. syscall_table_test resolves names
// through the kernel's own headers so the next one fails a test.
//
// the shape differs from x86_64 in one structural way worth knowing: aarch64
// has NO legacy non-`at` calls. no open, no stat, no fork, no pipe, no dup2,
// no getpgrp. libc uses openat, fstatat, clone, pipe2, dup3 and getpgid, so
// their absence is correct rather than an omission -- there is no number to
// allow.
// ---------------------------------------------------------------------------

inline SyscallPolicy base() {
    SyscallPolicy p;
    p.set_default(SysAction::errno_, 1 /* EPERM */);

    static constexpr SysNr kAllowed[] = {
        // what libc needs before main
        63,   // read
        64,   // write
        57,   // close
        80,   // fstat
        62,   // lseek
        222,  // mmap
        226,  // mprotect
        215,  // munmap
        214,  // brk
        134,  // rt_sigaction
        135,  // rt_sigprocmask
        139,  // rt_sigreturn
        29,   // ioctl
        67,   // pread64
        68,   // pwrite64
        65,   // readv
        66,   // writev
        124,  // sched_yield
        233,  // madvise
        172,  // getpid
        93,   // exit
        160,  // uname
        25,   // fcntl
        17,   // getcwd
        169,  // gettimeofday
        165,  // getrusage
        174,  // getuid
        176,  // getgid
        175,  // geteuid
        177,  // getegid
        173,  // getppid
        178,  // gettid
        98,   // futex
        123,  // sched_getaffinity
        96,   // set_tid_address
        113,  // clock_gettime
        115,  // clock_nanosleep
        94,   // exit_group
        131,  // tgkill
        56,   // openat      (there is no `open`)
        79,   // fstatat     (there is no `stat`/`lstat`/`newfstatat`)
        78,   // readlinkat  (there is no `readlink`)
        99,   // set_robust_list
        261,  // prlimit64
        278,  // getrandom
        293,  // rseq

        // job control. note getpgrp does not exist here; glibc's getpgrp()
        // calls getpgid(0).
        154,  // setpgid
        155,  // getpgid
        157,  // setsid
        156,  // getsid   -- and NOT 151/152, which are setfsuid/setfsgid

        // descriptors and polling
        59,   // pipe2   (there is no `pipe`)
        23,   // dup
        24,   // dup3    (there is no `dup2`)
        20,   // epoll_create1
        21,   // epoll_ctl
        22,   // epoll_pwait
        73,   // ppoll     (there is no `poll`)
        72,   // pselect6  (there is no `select`)
        179,  // sysinfo
        43,   // statfs
        44,   // fstatfs
    };
    p.allow(std::span<const SysNr>{kAllowed});

    // clone3: denied with ENOSYS, for the same reason as on x86_64. its flags
    // live behind a pointer that seccomp cannot read, so it is a hole straight
    // through the clone flag rules; ENOSYS makes glibc fall back to clone, which
    // we CAN filter, where EPERM would break pthread_create.
    p.deny(435 /* clone3 */, 38 /* ENOSYS */);

    // outright denials, killed rather than errno'd: nothing legitimate calls
    // these inside a sandbox, so a kill is an unmistakable audit signal.
    for (SysNr nr : {117u /* ptrace */, 40u /* mount */, 39u /* umount2 */,
                     41u /* pivot_root */, 51u /* chroot */, 97u /* unshare */,
                     268u /* setns */, 280u /* bpf */, 241u /* perf_event_open */,
                     105u /* init_module */, 106u /* delete_module */,
                     273u /* finit_module */, 104u /* kexec_load */, 142u /* reboot */})
        p.kill(nr);

    // ioctl by allow-list, not deny-list -- see the x86_64 block for why. the
    // request numbers are ARCH-INDEPENDENT (they encode a type/nr/size, not a
    // syscall number), so this is the same table, and it is 32-bit for the same
    // reason: the kernel truncates ioctl's cmd to `unsigned int`.
    static constexpr std::uint32_t kIoctlAllowed[] = {
        0x5401,  // TCGETS
        0x5402,  // TCSETS
        0x5403,  // TCSETSW
        0x5404,  // TCSETSF
        0x5405,  // TCGETA
        0x5409,  // TCSBRK
        0x540A,  // TCXONC
        0x540B,  // TCFLSH
        0x5413,  // TIOCGWINSZ
        0x5414,  // TIOCSWINSZ
        0x540F,  // TIOCGPGRP
        0x5410,  // TIOCSPGRP
        0x5429,  // TIOCGSID
        0x541B,  // FIONREAD
        0x5421,  // FIONBIO
        0x5450,  // FIONCLEX
        0x5451,  // FIOCLEX
        0x5411,  // TIOCOUTQ
    };
    p.allow_arg32_only(29 /* ioctl */, 1 /* request */,
                       std::span<const std::uint32_t>{kIoctlAllowed}, SysAction::errno_, 1);

    // W^X, same as x86_64. PROT_* values are arch-independent.
    static constexpr std::uint64_t kProtWriteExec = 0x2 | 0x4;
    p.deny_arg_all(222 /* mmap */, 2 /* prot */, kProtWriteExec, SysAction::errno_, 1);
    p.deny_arg_all(226 /* mprotect */, 2 /* prot */, kProtWriteExec, SysAction::errno_, 1);

    return p;
}

// CLONE_NEW* are arch-independent (they are kernel flag bits, not syscall
// numbers), so this is the same constant as x86_64 uses.
inline constexpr std::uint64_t kCloneNewNamespaces =
    0x00020000ull |  // CLONE_NEWNS
    0x02000000ull |  // CLONE_NEWCGROUP
    0x04000000ull |  // CLONE_NEWUTS
    0x08000000ull |  // CLONE_NEWIPC
    0x10000000ull |  // CLONE_NEWUSER
    0x20000000ull |  // CLONE_NEWPID
    0x40000000ull;   // CLONE_NEWNET

inline SyscallPolicy& add_processes(SyscallPolicy& p) {
    // no fork or vfork on aarch64: both are clone underneath, and clone is the
    // only number there is.
    for (SysNr nr : {220u /* clone */, 221u /* execve */, 260u /* wait4 */, 129u /* kill */,
                     281u /* execveat */})
        p.allow(nr);
    p.deny_arg_any(220 /* clone */, 0 /* flags */, kCloneNewNamespaces, SysAction::errno_, 1);
    return p;
}

inline SyscallPolicy with_processes() {
    SyscallPolicy p = base();
    add_processes(p);
    return p;
}

// the filesystem set, named once. it was briefly written out twice -- here and
// in compiler_with_network -- which is precisely how a table drifts: one copy
// gets a new syscall and the other silently does not.
inline constexpr SysNr kFsSyscalls[] = {
    46,   // ftruncate
    61,   // getdents64  (there is no `getdents`)
    34,   // mkdirat     (there is no `mkdir`)
    33,   // mknodat     (there is no `mknod`)
    52,   // fchmod
    53,   // fchmodat    (there is no `chmod`)
    54,   // fchownat
    35,   // unlinkat    (no `unlink`, and no `rmdir`)
    38,   // renameat    (there is no `rename`)
    37,   // linkat
    36,   // symlinkat   (there is no `symlink`)
    48,   // faccessat   (there is no `access`)
    88,   // utimensat
    47,   // fallocate
    276,  // renameat2
    291,  // statx
    439,  // faccessat2
};

inline SyscallPolicy with_filesystem() {
    SyscallPolicy p = base();
    p.allow(std::span<const SysNr>{kFsSyscalls});
    return p;
}

inline SyscallPolicy compiler() {
    SyscallPolicy p = with_filesystem();
    add_processes(p);
    return p;
}

inline SyscallPolicy with_network() {
    SyscallPolicy p = base();
    static constexpr SysNr kNet[] = {
        198,  // socket
        203,  // connect
        202,  // accept
        206,  // sendto
        207,  // recvfrom
        211,  // sendmsg
        212,  // recvmsg
        210,  // shutdown
        200,  // bind
        201,  // listen
        204,  // getsockname
        205,  // getpeername
        208,  // setsockopt
        209,  // getsockopt
        242,  // accept4
        243,  // recvmmsg
        269,  // sendmmsg
    };
    p.allow(std::span<const SysNr>{kNet});
    return p;
}

inline SyscallPolicy compiler_with_network() {
    SyscallPolicy p = with_network();
    p.allow(std::span<const SysNr>{kFsSyscalls});
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

}  // namespace clay::CLAY_PROFILES_NAMESPACE

// these are per-inclusion decisions, not global state. leaving them defined
// would mean a second include with a different CLAY_PROFILE_ARCH_* silently kept
// the first one's tables -- the include guard already makes that a trap, and a
// stale macro would make it a confusing one.
#undef CLAY_PROFILES_X86_64
#undef CLAY_PROFILES_AARCH64
#undef CLAY_PROFILES_NAMESPACE
