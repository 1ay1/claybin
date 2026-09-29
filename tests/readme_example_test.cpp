// the example from README.md, compiled and run as a test so the front page of
// the repo cannot drift from the actual api.

#include "harness.hpp"

#include "claybin/policy/policy.hpp"

using namespace clay;
using namespace clay::literals;
using namespace clay::test;

int main() {
    // --- README: the headline example ------------------------------------
    auto policy = Policy<Draft>{}
                      .read("/usr")
                      .read_write("/workspace")
                      .memory(512_MB)
                      .processes(64)
                      .wall_clock(30_s)
                      .seal();

    // composition is intersection. this can only ever be more restrictive.
    auto tighter = policy & Policy<Sealed>::nothing();

    CHECK(policy.subsumes(tighter));
    CHECK(policy.data().fs.effective("/workspace/a.c").subsumes(FileRights::write()));
    CHECK(tighter.data().fs.is_nothing());

    return finish("readme_example_test");
}
