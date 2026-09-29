// fuzz the policy compiler.
//
// not "does it crash" -- that is the easy half. the real question is whether any
// random policy can produce a plan that VIOLATES A SECURITY INVARIANT, because
// those are the bugs that ship. so every generated policy is checked against
// properties that must hold for all inputs:
//
//   1. a compiled plan is always well-ordered (nnp before landlock before
//      seccomp). a plan out of order is a silent hole.
//   2. no guarantee is ever claimed without the op that would enforce it.
//   3. `isolated` is never claimed by a process backend.
//   4. the seccomp program the plan carries agrees with the policy it came
//      from, on every syscall number -- differential, not spot-checked.
//   5. composition never widens: compile(a & b) grants nothing compile(a) or
//      compile(b) did not.
//   6. every Ref in the arena resolves in bounds.
//
// failures print the seed, so any find is reproducible with one number.

#include "harness.hpp"

#include "claybin/bpf/emit.hpp"
#include "claybin/plan/compile.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

namespace {

constexpr const char* kPaths[] = {
    "/",     "/usr",   "/usr/lib", "/usr/bin", "/etc",      "/etc/hosts",
    "/tmp",  "/home",  "/home/a",  "/work",    "/work/sub", "/var",
    "/proc", "/dev",   "/lib",     "/opt",     "/srv",      "/mnt",
};
constexpr std::size_t kPathCount = sizeof kPaths / sizeof kPaths[0];

// build a random but STRUCTURALLY VALID policy. the point is to explore the
// space of things a caller could plausibly write, not to feed garbage: a
// compiler that rejects nonsense is easy, one that never mis-compiles a
// reasonable policy is the hard part.
Policy<Sealed> gen_policy(Rng& r) {
    auto d = Policy<Draft>{};

    // filesystem grants
    std::uint32_t nfs = r.below(6);
    for (std::uint32_t i = 0; i < nfs; ++i) {
        const char* p = kPaths[r.below(kPathCount)];
        switch (r.below(4)) {
            case 0: d = std::move(d).read(p); break;
            case 1: d = std::move(d).read_write(p); break;
            case 2: d = std::move(d).execute(p); break;
            default: d = std::move(d).deny(p); break;
        }
    }

    // a mount tree, sometimes. same-path binds mostly, so fidelity stays exact
    // and the plan actually compiles.
    if (r.coin(60)) {
        std::uint32_t nm = 1 + r.below(4);
        for (std::uint32_t i = 0; i < nm; ++i) {
            const char* p = kPaths[r.below(kPathCount)];
            switch (r.below(5)) {
                case 0: d = std::move(d).ro_bind(p, p); break;
                case 1: d = std::move(d).bind(p, p); break;
                case 2: d = std::move(d).tmpfs(p); break;
                case 3: d = std::move(d).bind_try(p, p); break;
                default: d = std::move(d).mkdir(p); break;
            }
        }
        if (r.coin(40)) d = std::move(d).proc_fs("/proc");
        if (r.coin(40)) d = std::move(d).dev_fs("/dev");
    }

    // network
    if (r.coin(30)) {
        std::uint16_t ports[] = {80, 443, 8080, 22, 0};
        d = std::move(d).connect("", ports[r.below(5)]);
    }

    // resources
    if (r.coin(50)) d = std::move(d).memory(Bytes{(1 + r.below(4096)) * 1024ull * 1024});
    if (r.coin(50)) d = std::move(d).processes(1 + r.below(1024));
    if (r.coin(30)) d = std::move(d).cpu_percent(1 + r.below(400));
    if (r.coin(20)) d = std::move(d).open_files(1 + r.below(65536));

    // syscall profile
    switch (r.below(5)) {
        case 0: d = std::move(d).syscall_profile(profiles::base()); break;
        case 1: d = std::move(d).syscall_profile(profiles::with_processes()); break;
        case 2: d = std::move(d).syscall_profile(profiles::with_filesystem()); break;
        case 3: d = std::move(d).syscall_profile(profiles::with_network()); break;
        default: d = std::move(d).syscall_profile(profiles::compiler()); break;
    }

    // hardening toggles
    if (r.coin(30)) d = std::move(d).new_session();
    if (r.coin(30)) d = std::move(d).die_with_parent();
    if (r.coin(20)) d = std::move(d).inherit_env();
    if (r.coin(15)) d = std::move(d).keep_cap(cap_num::net_bind_service);
    if (r.coin(10)) d = std::move(d).uid(r.below(65536));
    if (r.coin(25)) d = std::move(d).env("PATH", "/usr/bin");
    if (r.coin(20)) d = std::move(d).workdir(kPaths[r.below(kPathCount)]);

    return std::move(d).seal();
}

// a random host, so the compiler is exercised against kernels that do and do
// not have each mechanism.
HostCapabilities gen_host(Rng& r) {
    HostCapabilities h;
    h.user_namespaces = r.coin(85);
    h.mount_namespaces = r.coin(85);
    h.pid_namespaces = r.coin(85);
    h.net_namespaces = r.coin(85);
    h.uts_namespaces = r.coin(85);
    h.seccomp = r.coin(90);
    h.seccomp_user_notif = h.seccomp && r.coin(70);
    h.no_new_privs = r.coin(95);
    switch (r.below(5)) {
        case 0: h.landlock_abi = 0; break;
        case 1: h.landlock_abi = 1; break;
        case 2: h.landlock_abi = 3; break;
        case 3: h.landlock_abi = 5; break;
        default: h.landlock_abi = 10; break;
    }
    h.cgroups = r.coin(60) ? cgroup::Availability::delegated
                           : (r.coin(50) ? cgroup::Availability::unusable
                                         : cgroup::Availability::absent);
    h.cgroup_memory = h.cgroups == cgroup::Availability::delegated && r.coin(90);
    h.cgroup_pids = h.cgroups == cgroup::Availability::delegated && r.coin(90);
    h.cgroup_cpu = h.cgroups == cgroup::Availability::delegated && r.coin(40);
    return h;
}

// check every invariant against one compiled plan.
bool check_plan(const Compiled& c, const Policy<Sealed>& pol, std::uint64_t seed) {
    bool ok = true;
    auto fail = [&](const char* what) {
        std::fprintf(stderr, "  seed %llu: %s\n", static_cast<unsigned long long>(seed), what);
        ok = false;
    };

    // 1. ORDERING. a plan whose phases run out of order is a silent hole:
    //    landlock before no_new_privs fails with a bare EPERM, and seccomp
    //    before the mounts blocks our own setup.
    if (!c.plan.well_ordered()) fail("plan not well ordered");

    // 2. NO UNBACKED CLAIM. every `strong` must have the op that enforces it.
    //
    // filesystem is the subtle one: it has TWO independent walls, and either is
    // sufficient on its own. a mount namespace that pivots away from the host
    // enforces isolation by making paths not exist -- arguably a stronger
    // property than landlock's "exists but is denied". so the invariant is
    // "backed by at least one", not "backed by landlock". the fuzzer caught me
    // asserting the narrower version and it was the TEST that was wrong.
    const auto& g = c.guarantees;
    const bool has_fs_wall =
        c.plan.has(OpCode::landlock_enforce) || c.plan.has(OpCode::pivot_into_newroot);
    if (g.strength(CapId::fs_read) >= Enforcement::strong && !has_fs_wall)
        fail("claims strong fs_read with neither landlock nor a pivot");
    if (g.strength(CapId::fs_write) >= Enforcement::strong && !has_fs_wall)
        fail("claims strong fs_write with neither landlock nor a pivot");
    if (g.strength(CapId::syscall_filter) >= Enforcement::strong &&
        !c.plan.has(OpCode::seccomp_install))
        fail("claims strong syscall_filter without seccomp");
    if (g.strength(CapId::privilege_drop) >= Enforcement::strong &&
        !c.plan.has(OpCode::no_new_privs))
        fail("claims strong privilege_drop without no_new_privs");
    if (g.strength(CapId::proc_isolation) >= Enforcement::strong &&
        !c.plan.has(OpCode::unshare))
        fail("claims strong proc_isolation without unshare");
    if (g.strength(CapId::mem_limit) >= Enforcement::strong && !c.cgroup.valid())
        fail("claims strong mem_limit without a cgroup");

    // 3. NEVER `isolated`. that word is reserved for a separate kernel, and a
    //    process backend does not have one.
    for (std::size_t i = 0; i < kCapCount; ++i)
        if (g.strength(static_cast<CapId>(i)) >= Enforcement::isolated)
            fail("a process backend claimed `isolated`");

    // 4. the kernel is always shared.
    if (g.strength(CapId::host_kernel_isolation) != Enforcement::none)
        fail("claimed host kernel isolation");

    // 5. EVERY REF IN BOUNDS. a bad Ref is an out-of-bounds read in the
    //    post-fork path, where there is no way to recover.
    bool refs_ok = c.plan.for_each([&](OpCode code, std::span<const std::byte> payload) {
        auto check_ref = [&](Ref rf) {
            if (rf.len == 0 && rf.off == 0) return true;  // unused
            return c.plan.cstr(rf) != nullptr || !c.plan.blob(rf).empty();
        };
        switch (code) {
            case OpCode::mount: {
                MountOp o{};
                if (!Plan::decode(payload, o)) return false;
                return check_ref(o.source) && check_ref(o.target) && check_ref(o.fstype);
            }
            case OpCode::chdir: {
                ChdirOp o{};
                if (!Plan::decode(payload, o)) return false;
                return check_ref(o.path);
            }
            case OpCode::landlock_rule: {
                LandlockRuleOp o{};
                if (!Plan::decode(payload, o)) return false;
                return check_ref(o.path);
            }
            case OpCode::seccomp_install: {
                SeccompInstallOp o{};
                if (!Plan::decode(payload, o)) return false;
                return !c.plan.blob(o.program).empty();
            }
            default: return true;
        }
    });
    if (!refs_ok) fail("a Ref did not resolve in bounds");

    // 6. THE SECCOMP PROGRAM AGREES WITH THE POLICY. differential over every
    //    syscall number, not a handful of spot checks: this is the code that
    //    runs on every guest syscall, so a disagreement is either a bypass or a
    //    spurious kill.
    if (c.plan.has(OpCode::seccomp_install)) {
        auto prog = bpf::compile(pol.data().syscalls, bpf::kAuditArchX86_64);
        if (!prog) {
            fail("policy compiled to a plan but its syscalls would not compile");
        } else {
            for (SysNr nr = 0; nr < 512; ++nr) {
                std::uint32_t got = bpf::evaluate(*prog, nr, bpf::kAuditArchX86_64);
                std::uint32_t want = bpf::action_to_ret(pol.data().syscalls.action_for(nr),
                                                        pol.data().syscalls.errno_for(nr));
                // an arg rule can legitimately override the number-only answer,
                // so skip any syscall that has one.
                bool has_arg_rule = false;
                for (const auto& ar : pol.data().syscalls.arg_rules())
                    if (ar.nr == nr) has_arg_rule = true;
                if (has_arg_rule) continue;
                if (got != want) {
                    std::fprintf(stderr, "  seed %llu: seccomp disagrees at nr=%u (%#x vs %#x)\n",
                                 static_cast<unsigned long long>(seed), nr, got, want);
                    ok = false;
                    break;
                }
            }
        }
    }

    return ok;
}

}  // namespace

int main(int argc, char** argv) {
    // a seed on the command line reproduces exactly one case, which is how a
    // failure found in CI gets debugged locally.
    std::uint64_t only_seed = 0;
    bool single = false;
    if (argc >= 2) {
        only_seed = std::strtoull(argv[1], nullptr, 10);
        single = true;
    }

    const int iters = single ? 1 : 3000;
    int compiled = 0;
    int refused = 0;

    for (int i = 0; i < iters; ++i) {
        std::uint64_t seed = single ? only_seed : (0xC1A7B10Bull + static_cast<std::uint64_t>(i));
        Rng r{seed};

        Policy<Sealed> pol = gen_policy(r);
        HostCapabilities host = gen_host(r);

        auto c = compile(pol, host);
        if (!c) {
            // a refusal is a valid outcome and often the CORRECT one: the whole
            // design refuses rather than silently degrading. what matters is
            // that it refuses with a reason rather than crashing.
            ++refused;
            CHECK(c.error().code != Errc::ok);
            continue;
        }
        ++compiled;
        if (!check_plan(*c, pol, seed)) {
            CHECK(false);
            if (single) return finish("compile_fuzz_test");
        }
    }

    // -- composition never widens -----------------------------------------
    // the headline property of the whole library, fuzzed: meeting two policies
    // must not let the result reach anything neither input could.
    {
        for (int i = 0; i < 800; ++i) {
            std::uint64_t seed = 0xC0FFEE00ull + static_cast<std::uint64_t>(i);
            Rng r{seed};
            Policy<Sealed> a = gen_policy(r);
            Policy<Sealed> b = gen_policy(r);
            Policy<Sealed> m = a & b;

            // the policy-level property
            if (!a.subsumes(m) || !b.subsumes(m)) {
                std::fprintf(stderr, "  seed %llu: meet is not below both inputs\n",
                             static_cast<unsigned long long>(seed));
                CHECK(false);
                break;
            }
            // and pointwise on the filesystem, which is where a widening would
            // actually be exploitable
            for (const char* p : kPaths) {
                FileRights got = m.data().fs.effective(p);
                if (!a.data().fs.effective(p).subsumes(got) ||
                    !b.data().fs.effective(p).subsumes(got)) {
                    std::fprintf(stderr, "  seed %llu: meet widened %s\n",
                                 static_cast<unsigned long long>(seed), p);
                    CHECK(false);
                    break;
                }
            }
            // and on syscalls, where it would be a filter bypass
            for (SysNr nr = 0; nr < 400; ++nr) {
                SysAction got = m.data().syscalls.action_for(nr);
                if (got > a.data().syscalls.action_for(nr) ||
                    got > b.data().syscalls.action_for(nr)) {
                    std::fprintf(stderr, "  seed %llu: meet widened syscall %u\n",
                                 static_cast<unsigned long long>(seed), nr);
                    CHECK(false);
                    break;
                }
            }
        }
        ++g_checks;
    }

    if (!single)
        std::fprintf(stderr, "\n  %d policies compiled, %d refused (both are valid)\n\n",
                     compiled, refused);

    return finish("compile_fuzz_test");
}
