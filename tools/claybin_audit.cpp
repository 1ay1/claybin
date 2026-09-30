// prints what the running kernel supports, and what ONE FIXED EXAMPLE policy
// compiles to on it.
//
// the example is hardcoded, and that is worth saying loudly because it does not
// look hardcoded from the outside: this program takes no arguments and ignores
// anything you pass it. i lost real time during a debugging session reading its
// output as though it described the invocation i had just typed -- it reported 2
// landlock rules and a 15-op plan while the actual plan had 77 ops, and that sent
// me looking in entirely the wrong place.
//
// to audit a REAL invocation, use `claybin-run --audit` with the flags you
// actually care about. it compiles the policy those flags describe and prints the
// same report. this program is for "what can this kernel do", not "what will my
// sandbox do".

#include <cstdio>
#include <cstring>

#include "claybin/linux/cgroup.hpp"
#include "claybin/plan/compile.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::literals;

int main(int argc, char** argv) {
    // refuse to silently ignore arguments. a tool that accepts flags and does
    // something unrelated to them is worse than one that has none.
    if (argc > 1) {
        bool help = std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0;
        std::fprintf(help ? stdout : stderr,
                     "claybin-audit: reports host capabilities and compiles one FIXED\n"
                     "example policy. it takes no arguments.\n"
                     "\n"
                     "to audit a real invocation, use:\n"
                     "  claybin-run --audit <the flags you care about> -- /bin/true\n");
        return help ? 0 : 2;
    }

    HostCapabilities h = probe_host();

    std::printf("HOST\n");
    std::printf("  user ns        %s\n", h.user_namespaces ? "yes" : "no");
    std::printf("  mount ns       %s\n", h.mount_namespaces ? "yes" : "no");
    std::printf("  pid ns         %s\n", h.pid_namespaces ? "yes" : "no");
    std::printf("  net ns         %s\n", h.net_namespaces ? "yes" : "no");
    std::printf("  seccomp        %s\n", h.seccomp ? "yes" : "no");
    std::printf("  user_notif     %s\n", h.seccomp_user_notif ? "yes" : "no");
    std::printf("  cgroup v2      %s\n", cgroup::to_string(h.cgroups));
    if (h.cgroups != cgroup::Availability::delegated) {
        auto cg = cgroup::probe();
        if (cg.reason[0]) std::printf("                 %s\n", cg.reason);
    }
    std::printf("  no_new_privs   %s\n", h.no_new_privs ? "yes" : "no");
    if (h.landlock_abi)
        std::printf("  landlock       abi %u\n", h.landlock_abi);
    else
        std::printf("  landlock       no\n");

    // the fixed example. changing it changes nothing about any real sandbox --
    // it is here to give the plan printer something to print.
    std::printf("\nEXAMPLE POLICY (fixed; not your arguments)\n");
    auto policy = Policy<Draft>{}
                      .read("/usr")
                      .read_write("/workspace")
                      .deny("/workspace/.git")
                      .memory(512_MB)
                      .processes(64)
                      .wall_clock(30_s)
                      .syscall_profile(profiles::compiler())
                      .seal();

    auto c = compile(policy, h);
    if (!c) {
        std::printf("\ncompile failed: %s (%s)\n", to_string(c.error().code).data(),
                    c.error().mechanism.data());
        return 1;
    }

    std::printf("\nPLAN  %zu ops, %zu bytes\n", c->plan.op_count(), c->plan.size());
    c->plan.for_each([](OpCode code, std::span<const std::byte>) {
        std::printf("  %-10s %s\n", to_string(phase_of(code)), to_string(code));
        return true;
    });

    std::printf("\nGUARANTEES\n");
    for (std::size_t i = 0; i < kCapCount; ++i) {
        auto id = static_cast<CapId>(i);
        std::printf("  %-24s %-9s %s\n", cap_name(id), to_string(c->guarantees.strength(id)),
                    c->guarantees.mechanism(id));
    }

    if (!c->degraded.empty()) {
        std::printf("\nDEGRADED (host cannot enforce)\n");
        for (CapId id : c->degraded) std::printf("  %s\n", cap_name(id));
    }
    return 0;
}
