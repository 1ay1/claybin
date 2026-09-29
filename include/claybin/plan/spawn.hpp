// claybin: a minimal spawn, for tests and for callers with no event loop.
//
// deliberately small. it forks, applies the plan, and execs. it does NOT
// supervise: no timeout, no output pumping, no reaping strategy. that is the
// loop's job (see docs/jaal.md), and claybin refuses to grow one.
//
// the one thing it does own is the fork/exec boundary itself, because that is
// where the async-signal-safety rules live and they are easy to get wrong.
#pragma once

#include <span>
#include <string_view>

#include "claybin/core/error.hpp"
#include "claybin/linux/cgroup.hpp"
#include "claybin/plan/plan.hpp"

namespace clay {

struct Command {
    const char* program{nullptr};
    // nullptr-terminated, exactly as execve wants them. no std::string here:
    // the child side of a fork cannot safely allocate.
    const char* const* argv{nullptr};
    const char* const* envp{nullptr};
};

struct Spawned {
    int pid{-1};
    int pidfd{-1};  // -1 if the kernel is too old for CLONE_PIDFD
};

// fork, apply the plan in the child, exec. returns in the parent only.
//
// on any failure inside the child the child _exit()s with a distinctive code
// rather than returning, because a child that survived a failed sandbox setup
// is unconfined and must not run the target program.
Result<Spawned> spawn(const Plan& plan, const Command& cmd);

// same, but also move the child into `cg` before it execs.
//
// the cgroup write happens in the PARENT, between fork and exec: writing to
// sysfs is not async-signal-safe, and after a pivot_root the child cannot even
// see /sys/fs/cgroup any more. the child waits on a pipe until we say go, so
// the limits are guaranteed to be in force before the target program's first
// instruction.
Result<Spawned> spawn_in(const Plan& plan, const Command& cmd, const cgroup::Group& cg);

// exit codes the child uses to report setup failure. chosen high to avoid
// colliding with ordinary program exits.
inline constexpr int kExitPlanFailed = 126;
inline constexpr int kExitExecFailed = 127;

}  // namespace clay
