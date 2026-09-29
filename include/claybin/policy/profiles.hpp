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
        435,  // clone3 -> ENOSYS is fine, but glibc probes it
    };
    p.allow(std::span<const SysNr>{kAllowed});

    // explicitly kill rather than errno for the classic escape attempts. a
    // denied-with-EPERM ptrace looks like a permissions hiccup; a killed one is
    // an unmistakable signal in an audit log.
    for (SysNr nr : {101u /* ptrace */, 165u /* mount */, 166u /* umount2 */,
                     155u /* pivot_root */, 161u /* chroot */, 272u /* unshare */,
                     308u /* setns */, 321u /* bpf */, 298u /* perf_event_open */,
                     175u /* init_module */, 176u /* delete_module */,
                     246u /* kexec_load */, 169u /* reboot */})
        p.kill(nr);

    return p;
}

// base plus threads and subprocesses. this is the smallest profile that works
// with spawn(), because it is the first one that allows execve.
inline SyscallPolicy with_processes() {
    SyscallPolicy p = base();
    for (SysNr nr : {56u /* clone */, 57u /* fork */, 58u /* vfork */, 59u /* execve */,
                     61u /* wait4 */, 62u /* kill */, 322u /* execveat */})
        p.allow(nr);
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
    for (SysNr nr : {56u, 57u, 58u, 59u, 61u, 62u, 322u}) p.allow(nr);
    return p;
}

#else

// the profiles are syscall-number tables, so they are arch-specific by nature.
// refuse rather than hand back a table for the wrong architecture.
inline SyscallPolicy base() { return SyscallPolicy::nothing(); }
inline SyscallPolicy with_processes() { return SyscallPolicy::nothing(); }
inline SyscallPolicy with_filesystem() { return SyscallPolicy::nothing(); }
inline SyscallPolicy compiler() { return SyscallPolicy::nothing(); }

#endif

}  // namespace clay::profiles
