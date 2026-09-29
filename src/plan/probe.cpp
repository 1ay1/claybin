// claybin: kernel capability probe.
//
// split from compile.cpp on purpose: compile() is pure and testable against a
// described kernel, this file is the only place that asks the real one.
#include "claybin/plan/compile.hpp"

#include "claybin/linux/cgroup.hpp"

#if defined(__linux__)
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace clay {

#if defined(__linux__)
namespace {

bool path_exists(const char* p) {
    struct stat st {};
    return ::stat(p, &st) == 0;
}

// read a small proc file into a buffer. returns false on any short read, so a
// missing knob is never mistaken for a permissive value.
bool read_small(const char* path, char* buf, std::size_t cap) {
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = ::read(fd, buf, cap - 1);
    ::close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return true;
}

std::uint32_t probe_landlock_abi() {
    // LANDLOCK_CREATE_RULESET_VERSION == 1. returns the abi version, or -1 with
    // ENOSYS/EOPNOTSUPP when landlock is absent or disabled.
    long rc = ::syscall(444 /* landlock_create_ruleset */, nullptr, 0ul, 1u);
    if (rc <= 0) return 0;
    return static_cast<std::uint32_t>(rc);
}

bool probe_seccomp() {
    // SECCOMP_GET_ACTION_AVAIL(2) with a null arg: EFAULT means seccomp is
    // there and validated our pointer, ENOSYS means it is not.
    long rc = ::syscall(SYS_seccomp, 2u, 0u, nullptr);
    if (rc == 0) return true;
    return errno == EFAULT || errno == EINVAL;
}

bool probe_user_notif() {
    std::uint32_t action = 0x7fc00000u;  // SECCOMP_RET_USER_NOTIF
    long rc = ::syscall(SYS_seccomp, 2u /* GET_ACTION_AVAIL */, 0u, &action);
    return rc == 0;
}

bool probe_userns() {
    char buf[32];
    // an explicit 0 here means the admin turned unprivileged userns off.
    if (read_small("/proc/sys/kernel/unprivileged_userns_clone", buf, sizeof buf))
        if (buf[0] == '0') return false;
    if (read_small("/proc/sys/user/max_user_namespaces", buf, sizeof buf))
        if (buf[0] == '0') return false;
    return path_exists("/proc/self/ns/user");
}

bool probe_cgroup2() {
    struct stat st {};
    return ::stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0;
}
bool probe_no_new_privs() {
    // reading the current value is harmless and tells us the knob exists.
    return ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) >= 0;
}

}  // namespace

HostCapabilities probe_host() {
    HostCapabilities h;
    h.user_namespaces = probe_userns();
    h.mount_namespaces = path_exists("/proc/self/ns/mnt");
    h.pid_namespaces = path_exists("/proc/self/ns/pid");
    h.net_namespaces = path_exists("/proc/self/ns/net");
    h.uts_namespaces = path_exists("/proc/self/ns/uts");
    h.seccomp = probe_seccomp();
    h.seccomp_user_notif = h.seccomp && probe_user_notif();

    // cgroups need the full delegation probe, not a stat: whether we can
    // actually create a limited cgroup depends on how our caller was launched.
    if (probe_cgroup2()) {
        auto cg = cgroup::probe();
        h.cgroups = cg.availability;
        h.cgroup_memory = cg.memory;
        h.cgroup_pids = cg.pids;
        h.cgroup_cpu = cg.cpu;
    }

    h.landlock_abi = probe_landlock_abi();
    h.no_new_privs = probe_no_new_privs();
    return h;
}

#else

HostCapabilities probe_host() { return HostCapabilities::none(); }

#endif

}  // namespace clay
