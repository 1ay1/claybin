// dump what the aarch64 profiles permit, for tests/aarch64_audit.sh to
// cross-check against the kernel's own syscall table.
//
// this is a separate binary rather than part of syscall_table_test because the
// point is INDEPENDENCE: the C++ test checks the numbers its author decided to
// check, and shares any misreading with the tables it is testing. the shell
// script resolves every number through <asm-generic/unistd.h> instead, so a
// wrong entry surfaces as a forbidden name or as a number that names nothing.
//
// the aarch64 tables have never executed -- no hardware here, no cross
// toolchain -- so this is the strongest check available short of real hardware.
#define CLAY_PROFILE_ARCH_AARCH64 1
#define CLAY_PROFILES_NAMESPACE profiles_aarch64_dump

#include <cstdio>

#include "claybin/policy/profiles.hpp"

using namespace clay;

int main() {
    struct Named {
        const char* name;
        SyscallPolicy policy;
    };
    const Named profiles[] = {
        {"base", profiles_aarch64_dump::base()},
        {"with_processes", profiles_aarch64_dump::with_processes()},
        {"with_filesystem", profiles_aarch64_dump::with_filesystem()},
        {"with_network", profiles_aarch64_dump::with_network()},
        {"compiler", profiles_aarch64_dump::compiler()},
        {"compiler_with_network", profiles_aarch64_dump::compiler_with_network()},
    };

    // 600 covers the generic table with room to spare; anything above it would
    // be a number no aarch64 kernel assigns.
    for (const auto& p : profiles) {
        for (SysNr nr = 0; nr < 600; ++nr) {
            SysAction a = p.policy.action_for(nr);
            if (a == SysAction::allow)
                std::printf("%s ALLOW %u\n", p.name, nr);
            else if (a == SysAction::kill_process)
                std::printf("%s KILL %u\n", p.name, nr);
        }
    }
    return 0;
}
