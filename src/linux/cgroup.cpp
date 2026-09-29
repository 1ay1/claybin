#include "claybin/linux/cgroup.hpp"

#if defined(__linux__)

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace clay::cgroup {
namespace {

constexpr const char* kRoot = "/sys/fs/cgroup";

// read a whole small file into a caller buffer. returns length, or -1.
long read_file(const char* path, char* buf, std::size_t cap) {
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = ::read(fd, buf, cap - 1);
    ::close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return static_cast<long>(n);
}

Status write_file(const std::string& path, const char* value) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return std::unexpected(Error{Errc::io_error, "cgroup: open", errno});
    ssize_t n = ::write(fd, value, std::strlen(value));
    int err = errno;
    ::close(fd);
    if (n < 0) return std::unexpected(Error{Errc::io_error, "cgroup: write", err});
    return {};
}

bool has_word(const char* haystack, const char* word) {
    std::size_t wl = std::strlen(word);
    const char* p = haystack;
    while ((p = std::strstr(p, word)) != nullptr) {
        bool left = (p == haystack) || p[-1] == ' ' || p[-1] == '\n';
        char r = p[wl];
        bool right = r == '\0' || r == ' ' || r == '\n';
        if (left && right) return true;
        p += wl;
    }
    return false;
}

// our own cgroup path, from /proc/self/cgroup. v2 lines look like "0::/path".
bool own_cgroup(std::string& out) {
    char buf[4096];
    if (read_file("/proc/self/cgroup", buf, sizeof buf) < 0) return false;
    // find the "0::" line: the unified hierarchy
    const char* line = buf;
    while (line && *line) {
        if (line[0] == '0' && line[1] == ':' && line[2] == ':') {
            const char* start = line + 3;
            const char* end = std::strchr(start, '\n');
            out.assign(start, end ? static_cast<std::size_t>(end - start) : std::strlen(start));
            return true;
        }
        line = std::strchr(line, '\n');
        if (line) ++line;
    }
    return false;
}

// count entries in cgroup.procs. the "no internal process" rule means a cgroup
// with any process in it cannot enable controllers in its subtree.
long count_procs(const std::string& dir) {
    std::string p = dir + "/cgroup.procs";
    char buf[8192];
    long n = read_file(p.c_str(), buf, sizeof buf);
    if (n < 0) return -1;
    long count = 0;
    for (long i = 0; i < n; ++i)
        if (buf[i] == '\n') ++count;
    return count;
}

}  // namespace

Probe probe() {
    Probe pr;

    // is cgroup v2 even mounted?
    char ctl[512];
    std::string root_ctl = std::string(kRoot) + "/cgroup.controllers";
    if (read_file(root_ctl.c_str(), ctl, sizeof ctl) < 0) {
        pr.reason = "cgroup v2 not mounted";
        return pr;
    }

    std::string rel;
    if (!own_cgroup(rel)) {
        pr.reason = "cannot read /proc/self/cgroup";
        return pr;
    }
    pr.own_path = std::string(kRoot) + (rel == "/" ? "" : rel);

    // which controllers are available TO US, which is what our own cgroup's
    // cgroup.controllers says -- the root's list is irrelevant if our parent
    // did not delegate them down.
    char mine[512] = "";
    std::string my_ctl = pr.own_path + "/cgroup.controllers";
    if (read_file(my_ctl.c_str(), mine, sizeof mine) < 0) {
        pr.reason = "cannot read our cgroup.controllers";
        return pr;
    }
    pr.memory = has_word(mine, "memory");
    pr.pids = has_word(mine, "pids");
    pr.cpu = has_word(mine, "cpu");
    pr.io = has_word(mine, "io");
    // can we actually delegate? the blocker is cgroup v2's no-internal-process
    // rule: controllers cannot be enabled in a cgroup's subtree while that
    // cgroup holds processes.
    //
    // that is almost always true of wherever we were launched -- even a fresh
    // `systemd-run --scope` contains the shell and its children. the standard
    // fix is to move OURSELVES (and anything else here) into a leaf child
    // first, which leaves the parent empty and free to delegate. that is a real
    // change to our own process's cgroup, so we only do it when the caller has
    // asked for limits, and we do it here in the probe only to a scratch cgroup
    // we immediately remove.
    std::string probe_dir = pr.own_path + "/.clay-probe";
    ::mkdir(probe_dir.c_str(), 0755);

    std::string subtree = pr.own_path + "/cgroup.subtree_control";
    // ask only for what we have; asking for an absent controller is its own EINVAL
    std::string want;
    if (pr.memory) want += "+memory ";
    if (pr.pids) want += "+pids ";
    if (pr.cpu) want += "+cpu";
    if (want.empty()) {
        ::rmdir(probe_dir.c_str());
        pr.availability = Availability::unusable;
        pr.reason = "no memory or pids controller delegated to us";
        return pr;
    }

    auto st = write_file(subtree, want.c_str());
    if (!st && st.error().sys_errno == EBUSY) {
        // the expected case. try the leaf dance: move every process here into
        // the scratch cgroup, then delegate, then move them back.
        std::string procs_path = pr.own_path + "/cgroup.procs";
        char procs[8192];
        long n = read_file(procs_path.c_str(), procs, sizeof procs);
        bool moved_any = false;
        if (n > 0) {
            std::string leaf_procs = probe_dir + "/cgroup.procs";
            const char* line = procs;
            while (line && *line) {
                const char* end = std::strchr(line, '\n');
                std::string pid(line, end ? static_cast<std::size_t>(end - line)
                                          : std::strlen(line));
                if (!pid.empty() && write_file(leaf_procs, pid.c_str())) moved_any = true;
                line = end ? end + 1 : nullptr;
            }
        }
        if (moved_any) st = write_file(subtree, want.c_str());

        // whatever happened, put everyone back where they were: leaving our own
        // process parked in a scratch cgroup we are about to rmdir would be
        // rude at best.
        char leaf_now[8192];
        std::string leaf_procs_r = probe_dir + "/cgroup.procs";
        long m = read_file(leaf_procs_r.c_str(), leaf_now, sizeof leaf_now);
        if (m > 0) {
            const char* line = leaf_now;
            while (line && *line) {
                const char* end = std::strchr(line, '\n');
                std::string pid(line, end ? static_cast<std::size_t>(end - line)
                                          : std::strlen(line));
                if (!pid.empty()) (void)write_file(procs_path, pid.c_str());
                line = end ? end + 1 : nullptr;
            }
        }
    }

    if (!st) {
        ::rmdir(probe_dir.c_str());
        pr.availability = Availability::unusable;
        // EBUSY even after the leaf dance means something else holds this
        // cgroup, and the fix is on the launching side, not in claybin.
        pr.reason = st.error().sys_errno == EBUSY
                        ? "cgroup holds processes we cannot move; launch in a delegated "
                          "scope (systemd-run --user --scope) for cgroup limits"
                        : "cannot enable controllers in our subtree";
        return pr;
    }

    // it worked. confirm the child actually got the controllers.
    char child_ctl[512] = "";
    std::string cc = probe_dir + "/cgroup.controllers";
    read_file(cc.c_str(), child_ctl, sizeof child_ctl);
    ::rmdir(probe_dir.c_str());

    // report what the CHILD actually got, not what we asked for: a controller
    // the parent has may still not be delegable down, and claiming otherwise is
    // how a cpu quota silently does nothing.
    pr.memory = has_word(child_ctl, "memory");
    pr.pids = has_word(child_ctl, "pids");
    pr.cpu = has_word(child_ctl, "cpu");
    pr.io = has_word(child_ctl, "io");

    if (!pr.memory && !pr.pids) {
        pr.availability = Availability::unusable;
        pr.reason = "subtree_control accepted but no controllers appeared";
        return pr;
    }

    pr.availability = Availability::delegated;
    return pr;
}

Result<Group> create(const Probe& pr, const ResourceLimits& limits,
                     std::string_view name_hint) {
    if (pr.availability != Availability::delegated)
        return std::unexpected(Error{Errc::unsupported, pr.reason});

    // a unique name, so concurrent sandboxes do not collide.
    char name[128];
    std::snprintf(name, sizeof name, "clay-%.*s-%d",
                  static_cast<int>(name_hint.size() > 32 ? 32 : name_hint.size()),
                  name_hint.data(), static_cast<int>(::getpid()));

    Group g;
    g.path_ = pr.own_path + "/" + name;

    if (::mkdir(g.path_.c_str(), 0755) < 0 && errno != EEXIST)
        return std::unexpected(Error{Errc::io_error, "cgroup: mkdir", errno});

    // hold a directory fd: after a pivot_root the path is gone, but an fd on it
    // still works, and it also means the attach cannot be redirected by a
    // symlink swap between create and attach.
    g.fd_ = ::open(g.path_.c_str(), O_DIRECTORY | O_CLOEXEC);
    if (g.fd_ < 0) {
        ::rmdir(g.path_.c_str());
        return std::unexpected(Error{Errc::io_error, "cgroup: open dir", errno});
    }

    char buf[32];
    auto set = [&](const char* file, std::uint64_t v) -> Status {
        std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
        return write_file(g.path_ + "/" + file, buf);
    };

    if (pr.memory && !limits.memory.is_unlimited()) {
        if (auto st = set("memory.max", limits.memory.value()); !st)
            return std::unexpected(st.error());
        // without this, the guest can exceed its memory cap by swapping. a
        // memory limit that swap defeats is not a memory limit.
        if (limits.memory_swap.is_unlimited())
            write_file(g.path_ + "/memory.swap.max", "0");
        else
            (void)set("memory.swap.max", limits.memory_swap.value());
    }

    if (pr.pids && !limits.pids.is_unlimited()) {
        if (auto st = set("pids.max", limits.pids.value()); !st)
            return std::unexpected(st.error());
    }

    if (pr.cpu && !limits.cpu_weight.is_unlimited()) {
        // cpu.weight is 1-10000; clamp rather than reject so a caller passing
        // a share count gets something sensible.
        std::uint64_t w = limits.cpu_weight.value();
        if (w == 0) w = 1;
        if (w > 10000) w = 10000;
        (void)set("cpu.weight", w);
    }

    // cpu.max is a HARD quota: "$MAX $PERIOD" microseconds of cpu per period.
    // this is the one that actually bounds a busy loop -- cpu.weight only
    // decides who wins when there is contention, so on an idle machine a
    // weight-limited guest still gets a whole core.
    if (pr.cpu && !limits.cpu_quota_percent.is_unlimited()) {
        std::uint64_t pct = limits.cpu_quota_percent.value();
        if (pct == 0) pct = 1;
        constexpr std::uint64_t kPeriod = 100000;  // 100ms, the kernel default
        std::uint64_t quota = (kPeriod * pct) / 100;
        if (quota == 0) quota = 1000;
        char q[64];
        std::snprintf(q, sizeof q, "%llu %llu", static_cast<unsigned long long>(quota),
                      static_cast<unsigned long long>(kPeriod));
        (void)write_file(g.path_ + "/cpu.max", q);
    }

    return g;
}

Status Group::attach(int pid) const {
    if (fd_ < 0) return std::unexpected(Error{Errc::invalid_policy, "cgroup: no group"});
    int fd = ::openat(fd_, "cgroup.procs", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return std::unexpected(Error{Errc::io_error, "cgroup: open procs", errno});
    char buf[32];
    int n = std::snprintf(buf, sizeof buf, "%d", pid);
    ssize_t w = ::write(fd, buf, static_cast<std::size_t>(n));
    int err = errno;
    ::close(fd);
    if (w < 0) return std::unexpected(Error{Errc::io_error, "cgroup: attach", err});
    return {};
}

void Group::release() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    if (!path_.empty()) {
        // only succeeds once the cgroup is empty, which is what we want: a
        // still-running sandbox keeps its cgroup alive.
        ::rmdir(path_.c_str());
        path_.clear();
    }
}

}  // namespace clay::cgroup

#else

namespace clay::cgroup {
Probe probe() {
    Probe p;
    p.reason = "cgroups are linux-only";
    return p;
}
Result<Group> create(const Probe& p, const ResourceLimits&, std::string_view) {
    return std::unexpected(Error{Errc::unsupported, p.reason});
}
Status Group::attach(int) const {
    return std::unexpected(Error{Errc::unsupported, "cgroups are linux-only"});
}
void Group::release() {}
}  // namespace clay::cgroup

#endif
