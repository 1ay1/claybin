// the escape corpus.
//
// one binary, many attacks. each one is a specific, named thing an attacker
// would actually try, and the harness records what happened rather than just
// asserting "blocked". the point is not to reach a number -- it is that every
// entry here is a claim about the sandbox that a reader can check.
//
// each attack returns:
//   0  = THE ESCAPE SUCCEEDED   (test failure)
//   1  = blocked                (test pass)
//   2  = not applicable here    (skipped, not counted as a pass)
#pragma once

#include <cstdio>
#include <cstring>

#if defined(__linux__)
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace clay::attacks {

#if defined(__linux__)

constexpr int kEscaped = 0;
constexpr int kBlocked = 1;
constexpr int kNotApplicable = 2;

// ---------------------------------------------------------------------------
// filesystem: reach something outside the granted tree
// ---------------------------------------------------------------------------

inline int read_path(const char* p) {
    int fd = ::open(p, O_RDONLY);
    if (fd < 0) return kBlocked;
    char b[1];
    ssize_t n = ::read(fd, b, 1);
    ::close(fd);
    return n > 0 ? kEscaped : kBlocked;
}

inline int write_path(const char* p) {
    int fd = ::open(p, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) return kBlocked;
    ::close(fd);
    ::unlink(p);
    return kEscaped;
}

inline int stat_path(const char* p) {
    struct stat st{};
    return ::stat(p, &st) == 0 ? kEscaped : kBlocked;
}

// climb out with .. -- the oldest trick, and the reason path normalization has
// to be component-aware rather than a string prefix.
inline int dotdot_climb() {
    return read_path("../../../../../../../../etc/passwd");
}

// a symlink we create ourselves, pointing outside. landlock resolves symlinks,
// so this must fail even though the symlink itself is inside the sandbox.
inline int symlink_escape() {
    if (::symlink("/etc/passwd", "/tmp/clay_esc_link") != 0) return kBlocked;
    int r = read_path("/tmp/clay_esc_link");
    ::unlink("/tmp/clay_esc_link");
    return r;
}

// walk /proc/*/root, which is a magic symlink to another process's root. if the
// pid namespace works there is nobody else to look at; if it does not, this
// reaches the host filesystem.
inline int proc_root_escape() {
    DIR* d = ::opendir("/proc");
    if (!d) return kBlocked;
    int result = kBlocked;
    while (struct dirent* e = ::readdir(d)) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        char path[256];
        std::snprintf(path, sizeof path, "/proc/%s/root/etc/passwd", e->d_name);
        if (read_path(path) == kEscaped) {
            result = kEscaped;
            break;
        }
    }
    ::closedir(d);
    return result;
}

// /proc/self/cwd and /proc/self/exe are magic symlinks too.
inline int proc_cwd_escape() { return read_path("/proc/self/cwd/../../../etc/passwd"); }

// openat with a dirfd we got before the sandbox closed things down. tests that
// inherited descriptors really are gone.
inline int inherited_fd_escape() {
    // fd 7 is what the harness leaks on purpose when testing this.
    char buf[1];
    ssize_t n = ::read(7, buf, 1);
    if (n >= 0) return kEscaped;
    return kBlocked;
}

// ---------------------------------------------------------------------------
// process: touch something outside our own tree
// ---------------------------------------------------------------------------

inline int ptrace_attach() {
    // pid 1 of the host, if we can see it
    long r = ::syscall(SYS_ptrace, PTRACE_ATTACH, 1, 0, 0);
    return r == 0 ? kEscaped : kBlocked;
}

inline int kill_host_init() {
    // signal pid 1. inside a pid namespace this is our own init, which is fine;
    // outside one it is the host's, which is not.
    return ::kill(1, 0) == 0 && ::getpid() != 1 ? kEscaped : kBlocked;
}

inline int fork_bomb() {
    int made = 0;
    for (int i = 0; i < 4096; ++i) {
        pid_t p = ::fork();
        if (p < 0) break;
        if (p == 0) {
            ::pause();
            ::_exit(0);
        }
        ++made;
    }
    for (int i = 0; i < made; ++i) ::wait(nullptr);
    // if we got thousands of processes the pid limit is not working
    return made > 2000 ? kEscaped : kBlocked;
}

inline int setuid_escape() {
    // becoming uid 0 OUTSIDE a user namespace would be an escape. inside one it
    // is meaningless, which is the point of userns.
    if (::setuid(0) != 0) return kBlocked;
    // we are uid 0 -- but can we actually do anything with it?
    return read_path("/etc/shadow") == kEscaped ? kEscaped : kBlocked;
}

inline int regain_caps() {
    // try to put a capability back into the bounding set. the kernel offers no
    // way to do this, which is the whole point of dropping it, but a missing
    // no_new_privs would let an suid exec do it.
    if (::prctl(PR_CAPBSET_READ, 21 /* CAP_SYS_ADMIN */, 0, 0, 0) == 1) return kEscaped;
    return kBlocked;
}

// ---------------------------------------------------------------------------
// namespaces: escape the ones we are in
// ---------------------------------------------------------------------------

inline int unshare_userns() {
    // a nested user namespace would give us capabilities in it, which is a
    // stepping stone to a mount escape.
    return ::unshare(CLONE_NEWUSER) == 0 ? kEscaped : kBlocked;
}

inline int setns_escape() {
    int fd = ::open("/proc/1/ns/mnt", O_RDONLY);
    if (fd < 0) return kBlocked;
    long r = ::syscall(SYS_setns, fd, 0);
    ::close(fd);
    return r == 0 ? kEscaped : kBlocked;
}

inline int mount_escape() {
    // remount the host root somewhere we can read it
    ::mkdir("/tmp/clay_esc_mnt", 0755);
    int r = ::mount("/", "/tmp/clay_esc_mnt", nullptr, MS_BIND, nullptr);
    if (r == 0) {
        int got = read_path("/tmp/clay_esc_mnt/etc/passwd");
        ::umount("/tmp/clay_esc_mnt");
        ::rmdir("/tmp/clay_esc_mnt");
        return got;
    }
    ::rmdir("/tmp/clay_esc_mnt");
    return kBlocked;
}

inline int pivot_root_escape() {
    long r = ::syscall(SYS_pivot_root, "/", "/");
    return r == 0 ? kEscaped : kBlocked;
}

inline int chroot_escape() {
    // the classic double-chroot: chroot into a subdir, then .. out past the old
    // root. only works if chroot is available at all.
    ::mkdir("/tmp/clay_esc_ch", 0755);
    if (::chroot("/tmp/clay_esc_ch") != 0) {
        ::rmdir("/tmp/clay_esc_ch");
        return kBlocked;
    }
    int r = read_path("../../../../etc/passwd");
    return r;
}

// ---------------------------------------------------------------------------
// kernel interfaces that are escapes in themselves
// ---------------------------------------------------------------------------

inline int bpf_load() {
    long r = ::syscall(SYS_bpf, 5 /* BPF_PROG_LOAD */, nullptr, 0);
    // EFAULT means bpf() is REACHABLE (it validated our null pointer), which is
    // the thing we care about -- a reachable bpf() is a kernel attack surface.
    return (r == 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

inline int perf_open() {
    long r = ::syscall(SYS_perf_event_open, nullptr, 0, -1, -1, 0);
    return (r >= 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

inline int userfaultfd_open() {
    // userfaultfd has been used in several kernel exploits as a way to win
    // otherwise-tight races.
    long r = ::syscall(323 /* userfaultfd */, 0);
    if (r >= 0) {
        ::close(static_cast<int>(r));
        return kEscaped;
    }
    return kBlocked;
}

inline int io_uring_open() {
    // io_uring bypasses seccomp for the operations it queues, which makes it a
    // sandbox escape by design rather than by bug. it must not be reachable.
    long r = ::syscall(425 /* io_uring_setup */, 1, nullptr);
    return (r >= 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

inline int kexec_load() {
    long r = ::syscall(SYS_kexec_load, 0, 0, nullptr, 0);
    return (r == 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

inline int module_load() {
    long r = ::syscall(SYS_init_module, nullptr, 0, "");
    return (r == 0 || errno == EFAULT) ? kEscaped : kBlocked;
}

// ---------------------------------------------------------------------------
// terminal: inject into the host's tty
// ---------------------------------------------------------------------------

inline int tiocsti_inject() {
    // push a byte into the terminal's input queue. if we share a controlling
    // terminal with an interactive shell, this TYPES INTO THAT SHELL and the
    // command runs outside the sandbox. one of the most underrated escapes.
    char c = 'X';
    if (::ioctl(0, 0x5412 /* TIOCSTI */, &c) == 0) return kEscaped;
    return kBlocked;
}

inline int tioclinux_inject() {
    // TIOCLINUX subcommand 2 can do the same via the selection buffer.
    char arg[2] = {2, 0};
    if (::ioctl(0, 0x541C /* TIOCLINUX */, arg) == 0) return kEscaped;
    return kBlocked;
}

inline int tioccons_steal() {
    if (::ioctl(1, 0x541D /* TIOCCONS */, nullptr) == 0) return kEscaped;
    return kBlocked;
}

// ---------------------------------------------------------------------------
// devices
// ---------------------------------------------------------------------------

inline int dev_mem_read() { return read_path("/dev/mem"); }
inline int dev_kmsg_read() { return read_path("/dev/kmsg"); }
inline int dev_kcore_read() { return read_path("/proc/kcore"); }
inline int sysrq_trigger() { return write_path("/proc/sysrq-trigger"); }

// ---------------------------------------------------------------------------
// information disclosure: things that leak the host even if we cannot touch it
// ---------------------------------------------------------------------------

inline int read_host_cmdline() {
    // another process's command line. inside a pid namespace with its own
    // procfs there should be nothing to read.
    return read_path("/proc/1/cmdline") == kEscaped && ::getpid() != 1 ? kEscaped : kBlocked;
}

inline int read_kallsyms() {
    // kernel symbol addresses defeat KASLR, which turns an unexploitable bug
    // into an exploitable one.
    return read_path("/proc/kallsyms");
}

inline int read_host_mounts() {
    // the host's mount table names paths that exist outside the sandbox. not an
    // escape by itself, but a map for one.
    int fd = ::open("/proc/self/mountinfo", O_RDONLY);
    if (fd < 0) return kBlocked;
    char buf[8192];
    ssize_t n = ::read(fd, buf, sizeof buf - 1);
    ::close(fd);
    if (n <= 0) return kBlocked;
    buf[n] = '\0';
    // if we can see the staging paths claybin used, the pivot leaked
    return std::strstr(buf, ".clay") != nullptr ? kEscaped : kBlocked;
}

inline int net_raw_socket() {
    int s = ::socket(AF_INET, SOCK_RAW, 255);
    if (s >= 0) {
        ::close(s);
        return kEscaped;
    }
    return kBlocked;
}

inline int abstract_unix_socket() {
    // an abstract AF_UNIX socket is NOT namespaced by the mount namespace -- it
    // lives in the network namespace. so without a netns a guest can talk to
    // host services listening on abstract addresses, which is a real and
    // frequently-missed hole.
    int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return kBlocked;
    // try a well-known abstract name that a desktop session usually has
    struct sockaddr_un {
        unsigned short family;
        char path[108];
    } a{};
    a.family = AF_UNIX;
    a.path[0] = '\0';
    std::memcpy(a.path + 1, "dbus-", 5);
    int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&a), 2 + 6);
    ::close(s);
    // ECONNREFUSED means the abstract namespace was REACHABLE, which is the
    // thing being tested -- not whether that particular name existed.
    return (r == 0 || errno == ECONNREFUSED) ? kEscaped : kBlocked;
}

// ---------------------------------------------------------------------------
// the table
// ---------------------------------------------------------------------------

struct Attack {
    const char* name;
    int (*run)();
    // some attacks only make sense under a particular policy, e.g. the fd leak
    // needs the harness to leak one first.
    bool needs_leaked_fd;
};

inline const Attack* table(std::size_t& count) {
    static const Attack t[] = {
        // filesystem
        {"fs.read_etc_shadow", [] { return read_path("/etc/shadow"); }, false},
        {"fs.read_etc_passwd", [] { return read_path("/etc/passwd"); }, false},
        {"fs.read_root_ssh", [] { return read_path("/root/.ssh/id_rsa"); }, false},
        {"fs.write_etc", [] { return write_path("/etc/clay_probe"); }, false},
        {"fs.write_usr", [] { return write_path("/usr/clay_probe"); }, false},
        {"fs.stat_home", [] { return stat_path("/home"); }, false},
        {"fs.dotdot_climb", dotdot_climb, false},
        {"fs.symlink_escape", symlink_escape, false},
        {"fs.proc_root", proc_root_escape, false},
        {"fs.proc_cwd", proc_cwd_escape, false},
        {"fs.inherited_fd", inherited_fd_escape, true},

        // process
        {"proc.ptrace_attach", ptrace_attach, false},
        {"proc.kill_host_init", kill_host_init, false},
        {"proc.fork_bomb", fork_bomb, false},
        {"proc.setuid_root", setuid_escape, false},
        {"proc.regain_caps", regain_caps, false},

        // namespaces
        {"ns.unshare_userns", unshare_userns, false},
        {"ns.setns", setns_escape, false},
        {"ns.mount_bind_root", mount_escape, false},
        {"ns.pivot_root", pivot_root_escape, false},
        {"ns.chroot_double", chroot_escape, false},

        // kernel interfaces
        {"kern.bpf", bpf_load, false},
        {"kern.perf_event_open", perf_open, false},
        {"kern.userfaultfd", userfaultfd_open, false},
        {"kern.io_uring", io_uring_open, false},
        {"kern.kexec_load", kexec_load, false},
        {"kern.init_module", module_load, false},

        // terminal
        {"tty.tiocsti", tiocsti_inject, false},
        {"tty.tioclinux", tioclinux_inject, false},
        {"tty.tioccons", tioccons_steal, false},

        // devices
        {"dev.mem", dev_mem_read, false},
        {"dev.kmsg", dev_kmsg_read, false},
        {"dev.kcore", dev_kcore_read, false},
        {"dev.sysrq", sysrq_trigger, false},

        // disclosure
        {"info.host_cmdline", read_host_cmdline, false},
        {"info.kallsyms", read_kallsyms, false},
        {"info.staging_paths", read_host_mounts, false},
        {"net.raw_socket", net_raw_socket, false},
        {"net.abstract_unix", abstract_unix_socket, false},
    };
    count = sizeof t / sizeof t[0];
    return t;
}

#endif  // __linux__

}  // namespace clay::attacks
