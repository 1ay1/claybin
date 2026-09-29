// prints what the running kernel supports and what a policy would compile to.
// this is the seed of `claybin audit`: everything here is a pure query over a
// compiled plan, so it works without spawning anything.

#include <cstdio>

#include "claybin/plan/compile.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::literals;

int main() {
    HostCapabilities h = probe_host();

    std::printf("HOST\n");
    std::printf("  user ns        %s\n", h.user_namespaces ? "yes" : "no");
    std::printf("  mount ns       %s\n", h.mount_namespaces ? "yes" : "no");
    std::printf("  pid ns         %s\n", h.pid_namespaces ? "yes" : "no");
    std::printf("  net ns         %s\n", h.net_namespaces ? "yes" : "no");
    std::printf("  seccomp        %s\n", h.seccomp ? "yes" : "no");
    std::printf("  user_notif     %s\n", h.seccomp_user_notif ? "yes" : "no");
    std::printf("  cgroup v2      %s\n", h.cgroup_v2 ? "yes" : "no");
    std::printf("  no_new_privs   %s\n", h.no_new_privs ? "yes" : "no");
    if (h.landlock_abi)
        std::printf("  landlock       abi %u\n", h.landlock_abi);
    else
        std::printf("  landlock       no\n");

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
