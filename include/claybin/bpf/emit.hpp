// claybin: classic-BPF emitter for seccomp.
//
// why not libseccomp: it emits a linear chain of compares, so a guest syscall
// walks O(n) instructions on *every* syscall it makes. with ~400 allowed
// numbers that is a real tax on syscall-heavy workloads.
//
// what we do instead:
//   1. fold the sorted rule set into maximal intervals of equal action
//      (~400 syscalls -> ~60 intervals, because allow-lists are dense in runs)
//   2. lay the intervals out as a balanced binary search tree
//   3. emit that tree as BPF jumps: ~4 instructions per level, ~6 levels
//
// so the guest pays O(log n) instead of O(n).
//
// this file is pure and platform-free: policy in, instructions out. no kernel
// headers, no syscalls. that means it builds and is unit-testable everywhere,
// including on machines that have never heard of seccomp. only install() is
// linux-only, and it lives elsewhere.
#pragma once

#include <cstdint>
#include <vector>

#include "claybin/core/error.hpp"
#include "claybin/policy/syscalls.hpp"

namespace clay::bpf {

// classic BPF instruction, layout-identical to struct sock_filter. we define it
// ourselves so this header does not drag in linux/filter.h.
struct Insn {
    std::uint16_t code;
    std::uint8_t jt;
    std::uint8_t jf;
    std::uint32_t k;

    friend bool operator==(const Insn&, const Insn&) = default;
};

// BPF opcode bits (from the classic BPF ISA; stable ABI, safe to hardcode).
inline constexpr std::uint16_t kLd = 0x00;
inline constexpr std::uint16_t kW = 0x00;
inline constexpr std::uint16_t kAbs = 0x20;
inline constexpr std::uint16_t kJmp = 0x05;
inline constexpr std::uint16_t kJa = 0x00;
inline constexpr std::uint16_t kJeq = 0x10;
inline constexpr std::uint16_t kJgt = 0x20;
inline constexpr std::uint16_t kJge = 0x30;
inline constexpr std::uint16_t kK = 0x00;
inline constexpr std::uint16_t kRet = 0x06;

// offsets into struct seccomp_data. stable kernel ABI.
inline constexpr std::uint32_t kOffNr = 0;
inline constexpr std::uint32_t kOffArch = 4;

// seccomp return actions.
inline constexpr std::uint32_t kRetKillProcess = 0x80000000u;
inline constexpr std::uint32_t kRetKillThread = 0x00000000u;
inline constexpr std::uint32_t kRetTrap = 0x00030000u;
inline constexpr std::uint32_t kRetErrno = 0x00050000u;
inline constexpr std::uint32_t kRetUserNotif = 0x7fc00000u;
inline constexpr std::uint32_t kRetLog = 0x7ffc0000u;
inline constexpr std::uint32_t kRetAllow = 0x7fff0000u;

// audit arch tokens, needed for the arch guard.
inline constexpr std::uint32_t kAuditArchX86_64 = 0xc000003eu;
inline constexpr std::uint32_t kAuditArchAarch64 = 0xc00000b7u;
inline constexpr std::uint32_t kAuditArchRiscv64 = 0xc00000f3u;

constexpr std::uint32_t action_to_ret(SysAction a, std::uint16_t err) {
    switch (a) {
        case SysAction::kill_process: return kRetKillProcess;
        case SysAction::kill_thread: return kRetKillThread;
        case SysAction::trap: return kRetTrap;
        case SysAction::errno_: return kRetErrno | (static_cast<std::uint32_t>(err) & 0xffffu);
        case SysAction::notify: return kRetUserNotif;
        case SysAction::log: return kRetLog;
        case SysAction::allow: return kRetAllow;
    }
    return kRetKillProcess;
}

// a maximal run of syscall numbers sharing one action.
struct Interval {
    SysNr lo;
    SysNr hi;  // inclusive
    std::uint32_t ret;

    friend bool operator==(const Interval&, const Interval&) = default;
};

struct Program {
    std::vector<Insn> insns;
    std::vector<Interval> intervals;  // kept for audit/explain output
    std::uint32_t default_ret{kRetKillProcess};
    std::uint32_t arch{kAuditArchX86_64};

    // depth of the emitted decision tree. the point of the whole exercise, so
    // it is worth asserting on in tests.
    std::uint32_t tree_depth{0};
};

// the arch this build targets. syscall-number-only filtering is exploitable on
// machines with more than one syscall convention, so the emitted program always
// guards on arch first and kills anything else.
constexpr std::uint32_t native_arch() {
#if defined(__x86_64__)
    return kAuditArchX86_64;
#elif defined(__aarch64__)
    return kAuditArchAarch64;
#elif defined(__riscv) && __riscv_xlen == 64
    return kAuditArchRiscv64;
#else
    return 0;  // compile() rejects this rather than emitting a weak filter
#endif
}

// fold a policy into maximal equal-action intervals, sorted by lo.
std::vector<Interval> fold_intervals(const SyscallPolicy& policy);

// compile to a BPF program. fails rather than emitting something weaker than
// asked for.
Result<Program> compile(const SyscallPolicy& policy, std::uint32_t arch = native_arch());

// tiny reference interpreter over struct seccomp_data, used by tests to
// differential-check the tree against a linear lookup. also handy for `explain`.
std::uint32_t evaluate(const Program& prog, std::uint32_t nr, std::uint32_t arch);

}  // namespace clay::bpf
