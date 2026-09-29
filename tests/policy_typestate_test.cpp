// typestate: the compile-time guarantees, checked with static_assert where
// possible so a regression is a build error rather than a test failure.

#include "harness.hpp"

#include <type_traits>

#include "claybin/core/witness.hpp"
#include "claybin/policy/policy.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

// ---------------------------------------------------------------------------
// compile-time shape of the api
//
// these are concepts rather than bare requires-expressions so the check is
// dependent: a ref-qualifier mismatch on `this` is a hard error in a
// non-dependent requires-expression, which would fail the build instead of
// yielding `false`.
// ---------------------------------------------------------------------------

template <class P> concept CanGrantRead = requires(P p) { p.read("/etc"); };
template <class P> concept CanSetMemory = requires(P p) { p.memory(1_MB); };
template <class P> concept CanConnect = requires(P p) { p.connect("evil.com", 443); };
template <class P> concept CanJoin = requires(P a, P b) { a | b; };
template <class P> concept CanMeet = requires(P a, P b) { a& b; };
template <class P> concept CanSealLvalue = requires(P p) { p.seal(); };
template <class P> concept CanSealRvalue = requires(P p) { std::move(p).seal(); };
template <class P> concept CanReadRvalue = requires(P p) { std::move(p).read("/usr"); };

// a sealed policy must not expose any way to gain authority.
static_assert(!CanGrantRead<Policy<Sealed>>);
static_assert(!CanSetMemory<Policy<Sealed>>);
static_assert(!CanConnect<Policy<Sealed>>);

// there must be no public join. `operator|` on policies would let a caller widen
// a sandbox, which is the one thing this design forbids.
static_assert(!CanJoin<Policy<Sealed>>);
static_assert(CanMeet<Policy<Sealed>>);

// seal() is rvalue-qualified: you must give up the draft to get a policy.
static_assert(!CanSealLvalue<Policy<Draft>>);
static_assert(CanSealRvalue<Policy<Draft>>);

// builders too, so a draft threads linearly instead of being aliased.
static_assert(!CanGrantRead<Policy<Draft>>);
static_assert(CanReadRvalue<Policy<Draft>>);

// a Witness cannot be forged: no public constructor.
static_assert(!std::is_default_constructible_v<Witness<cap::NetworkIsolation>>);
static_assert(!std::is_constructible_v<Witness<cap::NetworkIsolation>, Enforcement, const char*>);

int main() {
    // -- a fresh draft grants no authority ---------------------------------
    {
        auto p = Policy<Draft>{}.seal();
        CHECK(p.data().fs.is_nothing());
        CHECK(p.data().net.is_nothing());
        CHECK(p.data().env_cleared);
        CHECK(p.data().syscalls.default_action() == SysAction::kill_process);
        // resources are the exception, and it matters: a limit is a ceiling, so
        // lattice-bottom is 0, and RLIMIT_AS=0 means the child cannot map a
        // page -- execve fails with EACCES before main(). bottom is right for
        // permissions and wrong for ceilings.
        CHECK(p.data().resources.memory.is_unlimited());
        CHECK(p.data().resources.pids.is_unlimited());
    }

    // -- the builder chain -------------------------------------------------
    {
        auto p = Policy<Draft>{}
                     .read("/usr")
                     .read_write("/workspace")
                     .execute("/usr/bin")
                     .deny("/workspace/.git")
                     .memory(512_MB)
                     .processes(64)
                     .wall_clock(30_s)
                     .env("HOME", "/workspace")
                     .workdir("/workspace")
                     .seal();

        CHECK(p.data().fs.effective("/usr/lib").subsumes(FileRights::read()));
        CHECK(p.data().fs.effective("/usr/bin/gcc").subsumes(FileRights::exec()));
        CHECK(p.data().fs.effective("/workspace/a.c").subsumes(FileRights::write()));
        CHECK(p.data().fs.effective("/workspace/.git/config").is_nothing());
        CHECK(p.data().fs.effective("/home/ayush/.ssh/id_rsa").is_nothing());
        CHECK_EQ(p.data().resources.memory.value(), 512ull * 1024 * 1024);
        CHECK_EQ(p.data().workdir, std::string("/workspace"));
    }

    // -- composition tightens, never widens --------------------------------
    {
        auto broad = Policy<Draft>{}.read_write("/workspace").read("/usr").memory(2_GB).seal();
        auto tight = Policy<Draft>{}.read("/workspace").memory(256_MB).seal();

        auto both = broad & tight;
        CHECK(broad.subsumes(both));
        CHECK(tight.subsumes(both));
        // write got downgraded to read by the intersection
        CHECK(both.data().fs.effective("/workspace").subsumes(FileRights::read()));
        CHECK(!both.data().fs.effective("/workspace").subsumes(FileRights::write()));
        // /usr was only in one side, so it's gone
        CHECK(both.data().fs.effective("/usr").is_nothing());
        // tighter limit wins
        CHECK_EQ(both.data().resources.memory.value(), 256ull * 1024 * 1024);
    }

    // -- meeting with bottom yields bottom ---------------------------------
    {
        auto p = Policy<Draft>{}.read_write("/").memory(8_GB).seal();
        auto m = p & Policy<Sealed>::nothing();
        CHECK(m.data().fs.is_nothing());
        CHECK(m.data().resources.memory.is_nothing());
        // and it escalates the isolation level, never relaxes it
        CHECK(m.data().isolation == Isolation::microvm);
    }

    // -- stronger isolation wins in a meet ---------------------------------
    {
        auto a = Policy<Draft>{}.isolation(Isolation::process).seal();
        auto b = Policy<Draft>{}.isolation(Isolation::microvm).seal();
        CHECK((a & b).data().isolation == Isolation::microvm);
        CHECK((b & a).data().isolation == Isolation::microvm);
    }

    // -- env intersects by exact key AND value -----------------------------
    {
        auto a = Policy<Draft>{}.env("PATH", "/usr/bin").env("HOME", "/a").seal();
        auto b = Policy<Draft>{}.env("PATH", "/usr/bin").env("HOME", "/b").seal();
        auto m = a & b;
        CHECK_EQ(m.data().env.size(), std::size_t{1});
        CHECK_EQ(m.data().env[0].key, std::string("PATH"));
    }

    // -- guarantees are honest by default ----------------------------------
    {
        GuaranteeReport empty;
        // nothing recorded => nothing claimed
        CHECK(!empty.witness<cap::NetworkIsolation>().has_value());
        CHECK(empty.strength(CapId::fs_read) == Enforcement::none);

        GuaranteeReport::Builder b;
        b.record(CapId::net_isolation, Enforcement::strong, "netns");
        b.record(CapId::fs_read, Enforcement::strong, "landlock:abi5");
        b.record(CapId::host_kernel_isolation, Enforcement::none, "process-backend");
        auto rep = std::move(b).build();

        auto w = rep.witness<cap::NetworkIsolation>();
        CHECK(w.has_value());
        CHECK(w->strength() == Enforcement::strong);
        CHECK_EQ(std::string(w->mechanism()), std::string("netns"));

        // the process backend must NOT claim kernel isolation
        CHECK(!rep.witness<cap::HostKernelIsolation>().has_value());

        // a report is only as strong as its weakest asked-for mechanism
        CHECK(rep.weakest_of({CapId::net_isolation, CapId::fs_read}) == Enforcement::strong);
        CHECK(rep.weakest_of({CapId::net_isolation, CapId::mem_limit}) == Enforcement::none);
    }

    return finish("policy_typestate_test");
}
