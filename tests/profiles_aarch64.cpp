// the aarch64 syscall tables, compiled for aarch64 on whatever host is building.
//
// this exists so the tables can be TESTED. they are ~130 hand-written numbers,
// and the x86_64 list next to them shipped with one of them mislabelled (122 as
// "getsid", which is 124 -- 122 is setfsuid). a table nobody can run is a list
// of guesses, and cross-compiling the whole library to check it is a poor trade.
//
// CLAY_PROFILE_ARCH_AARCH64 selects which numbers the profile header emits. it
// cannot cause a filter for the wrong arch to be INSTALLED: bpf::compile()
// guards on the real audit arch from native_arch(), which is not overridable.
// so this is a data-only reinterpretation, which is exactly what a test wants.
// the arch's name is part of the namespace, so the two tables are DIFFERENT
// symbols rather than two definitions of the same inline function.
//
// this matters and it is not cosmetic: the first attempt put both in
// `clay::profiles`, and since the functions are inline the linker was free to
// pick either definition. it picked x86_64's for both, so the aarch64 "tests"
// were checking the x86_64 table against aarch64 numbers and failing in a way
// that looked like the table was wrong. the test caught it; a reviewer would
// not have.
#define CLAY_PROFILE_ARCH_AARCH64 1
#define CLAY_PROFILES_NAMESPACE profiles_aarch64

#include "claybin/policy/profiles.hpp"

namespace clay::arm {

SyscallPolicy base() { return profiles_aarch64::base(); }
SyscallPolicy with_processes() { return profiles_aarch64::with_processes(); }
SyscallPolicy with_filesystem() { return profiles_aarch64::with_filesystem(); }
SyscallPolicy with_network() { return profiles_aarch64::with_network(); }
SyscallPolicy compiler() { return profiles_aarch64::compiler(); }
SyscallPolicy compiler_with_network() { return profiles_aarch64::compiler_with_network(); }

}  // namespace clay::arm
