// claybin: cgroup v2 resource limits.
//
// this is the only mechanism in claybin that is not purely the sandboxed
// process's own business, and that shapes the whole design.
//
// cgroup v2 has a "no internal process" rule: you cannot enable controllers in
// a cgroup's subtree_control while that cgroup contains processes. so whether
// claybin can create a limited cgroup at all depends on HOW ITS CALLER WAS
// LAUNCHED, not on anything claybin does:
//
//   - launched into a delegated scope of its own (systemd-run --scope, a
//     container, a service unit with Delegate=yes): works, full strength.
//   - launched into a shared cgroup alongside sibling processes (a terminal,
//     a desktop session): the parent's subtree_control is EBUSY and there is
//     nothing we can do about it from inside.
//
// so `probe_host()` answers the question and the guarantee report tells the
// truth either way. what we must NOT do is claim `strong` on memory because
// cgroup2 is mounted, when the actual write is going to fail.
//
// the writes themselves are ordinary file writes, which means they happen
// PRE-FORK in the parent, not in the post-fork path: opening and writing
// sysfs files is not async-signal-safe, and the child cannot create its own
// cgroup anyway once it is in a user namespace. only the final "join this
// cgroup" write happens in the child, and even that is just one write to an
// already-open fd.
#pragma once

#include <cstdint>
#include <string>

#include "claybin/core/error.hpp"
#include "claybin/policy/resources.hpp"

namespace clay::cgroup {

// what the host lets us do with cgroups. three states, not a bool, because
// "mounted" and "usable by us" are very different things.
enum class Availability : std::uint8_t {
    // no cgroup v2 at all.
    absent = 0,
    // cgroup v2 is mounted, but our own cgroup cannot delegate: it has sibling
    // processes, so subtree_control is EBUSY. limits are rlimit-only.
    unusable = 1,
    // we can create a child cgroup with the controllers we need.
    delegated = 2,
};

constexpr const char* to_string(Availability a) {
    switch (a) {
        case Availability::absent: return "absent";
        case Availability::unusable: return "unusable (no delegation)";
        case Availability::delegated: return "delegated";
    }
    return "?";
}

struct Probe {
    Availability availability{Availability::absent};
    bool memory{false};
    bool pids{false};
    bool cpu{false};
    bool io{false};
    // our own cgroup's absolute path, e.g.
    // /sys/fs/cgroup/user.slice/.../app.scope
    std::string own_path;
    // why delegation is unavailable, for an honest error message
    const char* reason{""};
};

// ask the running kernel. linux only; elsewhere reports `absent`.
Probe probe();

// a created cgroup, with the limits already written. move-only: the destructor
// removes the directory, so a sandbox that never starts does not leak one.
class Group {
  public:
    Group() = default;
    Group(const Group&) = delete;
    Group& operator=(const Group&) = delete;
    Group(Group&& o) noexcept : path_(std::move(o.path_)), fd_(o.fd_) { o.fd_ = -1; }
    Group& operator=(Group&& o) noexcept {
        if (this != &o) {
            release();
            path_ = std::move(o.path_);
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }
    ~Group() { release(); }

    bool valid() const { return fd_ >= 0; }
    const std::string& path() const { return path_; }

    // an O_PATH-ish fd on the cgroup directory, so the child can join by
    // writing its pid to cgroup.procs without re-resolving a path that may no
    // longer exist after a pivot_root.
    int dirfd() const { return fd_; }

    // move a pid into this cgroup. called in the parent AFTER the fork, which
    // keeps the post-fork child path free of sysfs work.
    Status attach(int pid) const;

  private:
    void release();
    friend Result<Group> create(const Probe&, const ResourceLimits&, std::string_view);

    std::string path_;
    int fd_{-1};
};

// create a child cgroup under our own and write the limits into it.
//
// fails rather than silently skipping: a caller who asked for a 512 MB cap and
// got no cgroup needs to know, and `Compiled::guarantees` is how they find out.
Result<Group> create(const Probe& probe, const ResourceLimits& limits,
                     std::string_view name_hint);

}  // namespace clay::cgroup
