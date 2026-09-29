// the windows backend's translation, tested on whatever host happens to be
// running. the point of keeping compile() pure is exactly this: translation
// bugs are found here rather than on a windows box.
//
// what these tests really check is that the backend is HONEST. it is easy to
// write a windows backend that accepts every policy and reports `strong`; the
// value is in the places it says `partial` or refuses.

#include "harness.hpp"

#include "claybin/plan/compile.hpp"
#include "claybin/policy/shapes.hpp"
#include "claybin/windows/backend.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

int main() {
    const auto win = windows::HostCapabilities::modern_windows();

    // -- the headline honesty: NO SYSCALL FILTER ---------------------------
    // windows has no seccomp equivalent available to a normal process. a backend
    // that claimed `strong` here would be lying, and that lie is the whole
    // reason `Enforcement` is not a bool.
    {
        auto pol = shapes::system_ro().syscall_profile(profiles::base()).seal();
        auto c = windows::compile(pol, win);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->guarantees.strength(CapId::syscall_filter) == Enforcement::partial);
            // and it must NEVER be strong, whatever the policy says
            CHECK(c->guarantees.strength(CapId::syscall_filter) < Enforcement::strong);
        }
    }

    // -- hardened_process must be REFUSED on windows -----------------------
    // asking for every wall on a platform that cannot provide one of them is an
    // error, not an invitation to hand back less.
    {
        auto pol = shapes::system_ro()
                       .isolation(Isolation::hardened_process)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = windows::compile(pol, win);
        CHECK(!c.has_value());
        CHECK(c.error().code == Errc::unsupported);
    }

    // -- job objects really are as strong as cgroups ------------------------
    {
        auto pol = shapes::system_ro()
                       .memory(512_MB)
                       .processes(64)
                       .cpu_percent(50)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = windows::compile(pol, win);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->guarantees.strength(CapId::mem_limit) == Enforcement::strong);
            CHECK(c->guarantees.strength(CapId::pid_limit) == Enforcement::strong);
            CHECK(c->guarantees.strength(CapId::cpu_limit) == Enforcement::strong);
            CHECK_EQ(c->memory_limit_bytes, 512ull * 1024 * 1024);
            CHECK_EQ(c->active_process_limit, 64u);
            CHECK_EQ(c->cpu_rate_percent, 50ull);
        }
    }

    // -- cpu rate control needs win8; an older host says so -----------------
    {
        auto old = win;
        old.build = 7601;  // windows 7
        auto pol = shapes::system_ro().cpu_percent(50)
                       .syscall_profile(profiles::base()).seal();
        auto c = windows::compile(pol, old);
        CHECK(c.has_value());
        if (c) CHECK(c->guarantees.strength(CapId::cpu_limit) == Enforcement::none);
    }

    // -- no network authority => a genuinely strong network boundary --------
    {
        auto pol = shapes::system_ro().syscall_profile(profiles::base()).seal();
        auto c = windows::compile(pol, win);
        CHECK(c.has_value());
        if (c) {
            CHECK(!c->allow_network);
            CHECK(c->guarantees.strength(CapId::net_isolation) == Enforcement::strong);
        }
    }
    // -- but granting network downgrades the claim, since we have no WFP yet -
    {
        auto pol = shapes::system_ro()
                       .connect("api.github.com", 443)
                       .syscall_profile(profiles::base())
                       .seal();
        auto c = windows::compile(pol, win);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->allow_network);
            CHECK(c->guarantees.strength(CapId::net_isolation) == Enforcement::partial);
        }
    }

    // -- ACL mutation is OPT-IN, because it changes the HOST ----------------
    // every other claybin backend applies a policy only to the child. on windows
    // a filesystem grant means stamping ACEs on host objects, which is a side
    // effect outside the sandbox, so it must be asked for explicitly.
    {
        auto pol = shapes::builder("C:/work").seal();

        auto without = windows::compile(pol, win);
        CHECK(without.has_value());
        if (without) {
            CHECK(!without->acls_applied);
            // the grants are computed and reported, just not applied
            CHECK(!without->acl_grants.empty());
            CHECK(without->guarantees.strength(CapId::fs_write) == Enforcement::partial);
        }

        windows::Options opts;
        opts.allow_host_acl_mutation = true;
        auto with = windows::compile(pol, win, opts);
        CHECK(with.has_value());
        if (with) {
            CHECK(with->acls_applied);
            // still only partial: ACLs cannot express "subtree except this",
            // and newly created objects inherit the parent's ACL, not ours.
            CHECK(with->guarantees.strength(CapId::fs_write) == Enforcement::partial);
            CHECK(with->guarantees.strength(CapId::fs_write) < Enforcement::strong);
        }
    }

    // -- a remapping mount plan is refused, same as on a mountless linux ----
    {
        auto pol = shapes::app_container("C:/app", "C:/data").seal();
        auto c = windows::compile(pol, win);
        CHECK(!c.has_value());
        CHECK(c.error().code == Errc::unsupported);
    }

    // -- a portable shape compiles on windows AND linux, same policy --------
    // this is the actual cross-platform claim, so it is worth one direct test.
    {
        auto pol = shapes::builder("/work").seal();

        auto on_win = windows::compile(pol, win);
        CHECK(on_win.has_value());

        auto on_linux = clay::compile(pol, clay::HostCapabilities::modern_linux());
        CHECK(on_linux.has_value());

        if (on_win && on_linux) {
            // both enforce process isolation and resource limits strongly...
            CHECK(on_win->guarantees.strength(CapId::proc_isolation) == Enforcement::strong);
            CHECK(on_linux->guarantees.strength(CapId::proc_isolation) == Enforcement::strong);
            // ...and both agree the kernel is shared
            CHECK(on_win->guarantees.strength(CapId::host_kernel_isolation) == Enforcement::none);
            CHECK(on_linux->guarantees.strength(CapId::host_kernel_isolation) ==
                  Enforcement::none);
            // but linux is STRICTLY stronger on the two axes windows lacks
            CHECK(on_linux->guarantees.strength(CapId::syscall_filter) >
                  on_win->guarantees.strength(CapId::syscall_filter));
            CHECK(on_linux->guarantees.strength(CapId::fs_read) >
                  on_win->guarantees.strength(CapId::fs_read));
        }
    }

    // -- no appcontainer at all: degrade loudly ----------------------------
    {
        auto bare = windows::HostCapabilities::none();
        bare.job_objects = true;  // ancient windows: jobs but no appcontainer
        auto pol = shapes::system_ro().memory(256_MB)
                       .syscall_profile(profiles::base()).seal();
        auto c = windows::compile(pol, bare);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->guarantees.strength(CapId::proc_isolation) == Enforcement::none);
            CHECK(c->guarantees.strength(CapId::fs_read) == Enforcement::none);
            CHECK(!c->degraded.empty());
            // but the job object still works, so limits survive
            CHECK(c->guarantees.strength(CapId::mem_limit) == Enforcement::strong);
        }
    }

    // -- mitigation policies pick up what they can -------------------------
    {
        // a profile with no fork/exec maps exactly onto CHILD_PROCESS_RESTRICTED
        auto no_children = shapes::strict().seal();
        auto c1 = windows::compile(no_children, win);
        CHECK(c1.has_value());
        if (c1) CHECK(c1->disable_child_processes);

        // one that allows exec must not set it
        auto with_exec = shapes::system_ro()
                             .syscall_profile(profiles::compiler())
                             .allow_exec()
                             .seal();
        auto c2 = windows::compile(with_exec, win);
        CHECK(c2.has_value());
        if (c2) CHECK(!c2->disable_child_processes);
    }

    return finish("windows_backend_test");
}
