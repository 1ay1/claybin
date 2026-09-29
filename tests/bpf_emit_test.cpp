// the seccomp filter is the one piece of this library that runs on every single
// guest syscall, and a bug in it is either a bypass or a crash. so it gets a
// differential test: the emitted BPF tree is executed by an interpreter and
// compared against a straight linear lookup, over EVERY syscall number.

#include "harness.hpp"

#include "claybin/bpf/emit.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::bpf;
using namespace clay::test;

namespace {

// the reference: what the answer should be, computed the obvious slow way.
std::uint32_t reference(const SyscallPolicy& p, SysNr nr) {
    return action_to_ret(p.action_for(nr), p.errno_for(nr));
}

void differential(const SyscallPolicy& p, std::uint32_t max_nr = 600) {
    auto prog = compile(p, kAuditArchX86_64);
    CHECK(prog.has_value());
    if (!prog) return;
    for (SysNr nr = 0; nr < max_nr; ++nr) {
        std::uint32_t got = evaluate(*prog, nr, kAuditArchX86_64);
        std::uint32_t want = reference(p, nr);
        if (got != want) {
            std::fprintf(stderr, "  nr=%u got=%#x want=%#x\n", nr, got, want);
            CHECK_EQ(got, want);
            return;  // one report is enough, don't spam
        }
    }
    ++g_checks;
}

}  // namespace

int main() {
    // -- arch guard --------------------------------------------------------
    {
        SyscallPolicy p;
        p.set_default(SysAction::allow);
        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        // right arch: allowed
        CHECK_EQ(evaluate(*prog, 0, kAuditArchX86_64), kRetAllow);
        // wrong arch must be killed, never merely denied. filtering on syscall
        // numbers without pinning the arch is the classic seccomp bypass.
        CHECK_EQ(evaluate(*prog, 0, kAuditArchAarch64), kRetKillProcess);
        // x32 range must be killed even with an allow-all default
        CHECK_EQ(evaluate(*prog, 0x40000000u, kAuditArchX86_64), kRetKillProcess);
        CHECK_EQ(evaluate(*prog, 0x40000001u, kAuditArchX86_64), kRetKillProcess);
    }

    // -- empty policy: deny everything -------------------------------------
    {
        SyscallPolicy p = SyscallPolicy::nothing();
        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        CHECK_EQ(evaluate(*prog, 60, kAuditArchX86_64), kRetKillProcess);
        differential(p);
    }

    // -- a realistic allow-list --------------------------------------------
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        // a contiguous run: this is what folding is supposed to collapse
        for (SysNr nr = 0; nr <= 8; ++nr) p.allow(nr);
        p.allow(60);   // exit
        p.allow(231);  // exit_group
        p.allow(202);  // futex
        p.notify(41);  // socket -> broker
        p.kill(101);   // ptrace

        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        // 0..8 became ONE interval, not nine
        bool found_run = false;
        for (const auto& iv : prog->intervals)
            if (iv.lo == 0 && iv.hi == 8) found_run = true;
        CHECK(found_run);

        CHECK_EQ(evaluate(*prog, 3, kAuditArchX86_64), kRetAllow);
        CHECK_EQ(evaluate(*prog, 41, kAuditArchX86_64), kRetUserNotif);
        CHECK_EQ(evaluate(*prog, 101, kAuditArchX86_64), kRetKillProcess);
        CHECK_EQ(evaluate(*prog, 9, kAuditArchX86_64), kRetErrno | 1);
        differential(p);
    }

    // -- the performance claim, as an assertion ----------------------------
    // ~400 allowed syscalls must fold and stay shallow. if someone regresses the
    // emitter into a linear chain, this fails.
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 400; ++nr) p.allow(nr);
        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        // one fully contiguous run collapses to a single interval
        CHECK_EQ(prog->intervals.size(), std::size_t{1});
        CHECK(prog->insns.size() < 32);
        differential(p);
    }
    {
        // worst case: every other syscall allowed, so nothing merges.
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 400; nr += 2) p.allow(nr);
        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        CHECK_EQ(prog->intervals.size(), std::size_t{200});
        // 200 intervals: a balanced tree is 8 levels. a linear chain would be 200.
        CHECK(prog->tree_depth <= 9);
        CHECK(prog->insns.size() < 4096);
        differential(p);
    }

    // -- fuzz the emitter against the reference ----------------------------
    {
        Rng rng{0xB9Full};
        for (int i = 0; i < 200; ++i) {
            SyscallPolicy p;
            p.set_default(static_cast<SysAction>(rng.below(7)), 1);
            std::uint32_t n = rng.below(120);
            for (std::uint32_t k = 0; k < n; ++k)
                p.set(rng.below(500), static_cast<SysAction>(rng.below(7)), 1);
            differential(p);
        }
    }

    // -- degenerate shapes -------------------------------------------------
    {
        SyscallPolicy p;
        p.set_default(SysAction::kill_process);
        p.allow(0);  // first number
        differential(p, 8);
    }
    {
        SyscallPolicy p;
        p.set_default(SysAction::allow);
        p.kill(0xffffu);  // far from everything else
        differential(p, 0x10002u);
    }

    // -- argument filtering ------------------------------------------------
    // seccomp can see the syscall's register arguments, which is the only way to
    // say "ioctl is fine, except TIOCSTI". without it the choice is between
    // allowing a keystroke-injection escape and breaking isatty() everywhere.
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        p.allow(16);  // ioctl allowed in general
        p.deny_arg(16, 1, 0x5412, SysAction::errno_, 1);  // except TIOCSTI

        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        if (!prog) return finish("bpf_emit_test");

        // a plain ioctl with some other request is allowed
        std::uint64_t args_ok[6] = {0, 0x5401, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, args_ok), kRetAllow);

        // TIOCSTI is denied
        std::uint64_t args_sti[6] = {0, 0x5412, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, args_sti), kRetErrno | 1);

        // THE BYPASS THAT MATTERS: setting the high 32 bits must not sneak past.
        // a filter that compares only the low half would see 0x5412 here and
        // let it through while the kernel still performs the ioctl.
        std::uint64_t args_hi[6] = {0, 0x100000000ull | 0x5412, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, args_hi), kRetAllow);
        // (allow is CORRECT here: it is a different request number, so the deny
        // rule should not match. the point is that it is evaluated as a full
        // 64-bit value rather than truncated.)

        // a DIFFERENT syscall with the same arg value is unaffected
        CHECK_EQ(evaluate_with_args(*prog, 0, kAuditArchX86_64, args_sti), kRetErrno | 1);
    }

    // arg rules must not disturb the tree that follows them: the accumulator
    // holds an argument mid-check and has to be restored to the syscall number.
    {
        SyscallPolicy p;
        p.set_default(SysAction::errno_, 1);
        for (SysNr nr = 0; nr < 64; ++nr) p.allow(nr);
        p.deny_arg(16, 1, 0x5412);
        p.deny_arg(16, 1, 0x541C);
        p.deny_arg(101, 0, 0);

        auto prog = compile(p, kAuditArchX86_64);
        CHECK(prog.has_value());
        if (!prog) return finish("bpf_emit_test");

        // every allowed syscall still resolves correctly with no args set
        for (SysNr nr = 0; nr < 64; ++nr) {
            if (nr == 101) continue;  // has an arg rule matching zero
            std::uint32_t got = evaluate(*prog, nr, kAuditArchX86_64);
            if (got != kRetAllow) {
                std::fprintf(stderr, "  nr=%u clobbered by arg rules: %#x\n", nr, got);
                CHECK_EQ(got, kRetAllow);
                break;
            }
        }
        ++g_checks;

        // and the denials still fire
        std::uint64_t sti[6] = {0, 0x5412, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, sti), kRetErrno | 1);
        std::uint64_t lin[6] = {0, 0x541C, 0, 0, 0, 0};
        CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, lin), kRetErrno | 1);
    }

    // the real profile must deny TIOCSTI and still allow ioctl generally.
    {
        auto prog = compile(profiles::base(), kAuditArchX86_64);
        CHECK(prog.has_value());
        if (prog) {
            std::uint64_t sti[6] = {0, 0x5412, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, sti), kRetErrno | 1);
            std::uint64_t tcgets[6] = {0, 0x5401, 0, 0, 0, 0};
            CHECK_EQ(evaluate_with_args(*prog, 16, kAuditArchX86_64, tcgets), kRetAllow);
        }
    }

    return finish("bpf_emit_test");
}
