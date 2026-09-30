// the example from README.md, compiled and run as a test so the front page of
// the repo cannot drift from the actual api.

#include "harness.hpp"

#include "claybin/plan/compile.hpp"
#include "claybin/policy/policy.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::literals;
using namespace clay::test;

int main() {
    // --- README: the headline example ------------------------------------
    auto policy = Policy<Draft>{}
                      .ro_bind("/usr", "/usr")        // build a tree, bubblewrap-style
                      .bind("/workspace", "/work")
                      .deny("/work/.git")             // ...and punch a landlock hole in it
                      .tmpfs("/tmp", 64_MB)
                      .memory(512_MB)
                      .syscall_profile(profiles::compiler())
                      .seal();

    auto compiled = compile(policy, HostCapabilities::modern_linux());
    CHECK(compiled.has_value());
    if (!compiled) return finish("readme_example_test");

    auto ok = compiled->require(Enforcement::strong,
                                {CapId::fs_read, CapId::syscall_filter});
    CHECK(ok.has_value());

    // the tree was built, and both walls are in the plan
    CHECK(compiled->plan.has(OpCode::pivot_root));
    CHECK(compiled->plan.has(OpCode::landlock_enforce));
    CHECK(compiled->plan.has(OpCode::seccomp_install));
    CHECK(compiled->plan.well_ordered());

    // composition is intersection: it can only ever be more restrictive.
    auto tighter = policy & Policy<Sealed>::nothing();
    CHECK(policy.subsumes(tighter));
    // grants_nothing: the paths are still named, with zero rights. see
    // FsAuthority::is_nothing for why those are different questions.
    CHECK(tighter.data().fs.grants_nothing());

    return finish("readme_example_test");
}
