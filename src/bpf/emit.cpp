#include "claybin/bpf/emit.hpp"

#include <algorithm>
#include <cstddef>

namespace clay::bpf {
namespace {

constexpr Insn ld_abs(std::uint32_t off) { return Insn{kLd | kW | kAbs, 0, 0, off}; }
constexpr Insn jeq(std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return Insn{kJmp | kJeq | kK, jt, jf, k};
}
constexpr Insn jgt(std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return Insn{kJmp | kJgt | kK, jt, jf, k};
}
constexpr Insn jge(std::uint32_t k, std::uint8_t jt, std::uint8_t jf) {
    return Insn{kJmp | kJge | kK, jt, jf, k};
}
constexpr Insn ja(std::uint32_t off) { return Insn{kJmp | kJa, 0, 0, off}; }
constexpr Insn ret(std::uint32_t k) { return Insn{kRet | kK, 0, 0, k}; }

// x86_64 tags x32 syscalls with this bit. filtering on the number alone while
// ignoring it is the classic seccomp bypass, so we reject the whole range.
constexpr std::uint32_t kX32SyscallBit = 0x40000000u;

class TreeEmitter {
  public:
    TreeEmitter(const std::vector<Interval>& ivs, std::uint32_t default_ret)
        : ivs_(ivs), default_ret_(default_ret) {}

    void emit(std::vector<Insn>& out) {
        out_ = &out;
        build(0, static_cast<long>(ivs_.size()) - 1, 1);
        // one shared default block at the tail; every miss lands here.
        std::size_t def = out_->size();
        out_->push_back(ret(default_ret_));
        for (std::size_t site : default_sites_) patch_ja(site, def);
    }

    std::uint32_t depth() const { return depth_; }

  private:
    // node layout (4 instructions, subtrees inline):
    //   [0] JGT hi   -> [1] if above the interval, else [2]
    //   [1] JA right    (32-bit target, so a big tree can never overflow a jump)
    //   [2] JGE lo   -> [3] if inside, else [4]
    //   [3] RET action
    //   [4] left subtree, emitted inline so its offset is always reachable
    //   ... right subtree, reached by the JA above
    void build(long lo, long hi, std::uint32_t level) {
        if (lo > hi) {
            default_sites_.push_back(out_->size());
            out_->push_back(ja(0));
            return;
        }
        depth_ = std::max(depth_, level);
        long mid = lo + (hi - lo) / 2;
        const Interval& iv = ivs_[static_cast<std::size_t>(mid)];

        out_->push_back(jgt(iv.hi, 0, 1));
        std::size_t right_site = out_->size();
        out_->push_back(ja(0));
        out_->push_back(jge(iv.lo, 0, 1));
        out_->push_back(ret(iv.ret));

        build(lo, mid - 1, level + 1);
        patch_ja(right_site, out_->size());
        build(mid + 1, hi, level + 1);
    }

    void patch_ja(std::size_t site, std::size_t target) {
        (*out_)[site].k = static_cast<std::uint32_t>(target - (site + 1));
    }

    const std::vector<Interval>& ivs_;
    std::uint32_t default_ret_;
    std::vector<Insn>* out_{nullptr};
    std::vector<std::size_t> default_sites_;
    std::uint32_t depth_{0};
};

}  // namespace

std::vector<Interval> fold_intervals(const SyscallPolicy& policy) {
    std::uint32_t def = action_to_ret(policy.default_action(), policy.default_errno());

    std::vector<Interval> singles;
    singles.reserve(policy.rules().size());
    for (const auto& r : policy.rules()) {
        std::uint32_t rv = action_to_ret(r.action, r.errno_value);
        if (rv == def) continue;  // the default already says this
        singles.push_back({r.nr, r.nr, rv});
    }
    std::sort(singles.begin(), singles.end(),
              [](const Interval& a, const Interval& b) { return a.lo < b.lo; });

    // merge contiguous runs with the same action. allow-lists are dense in runs
    // (read/write/open/close/stat... are adjacent numbers), so this is where the
    // ~400 -> ~60 collapse comes from.
    std::vector<Interval> out;
    out.reserve(singles.size());
    for (const auto& iv : singles) {
        if (!out.empty() && out.back().ret == iv.ret && out.back().hi + 1 == iv.lo) {
            out.back().hi = iv.hi;
        } else {
            out.push_back(iv);
        }
    }
    return out;
}

Result<Program> compile(const SyscallPolicy& policy, std::uint32_t arch) {
    if (arch == 0)
        return std::unexpected(Error{Errc::unsupported, "seccomp: unknown audit arch"});

    Program prog;
    prog.arch = arch;
    prog.default_ret = action_to_ret(policy.default_action(), policy.default_errno());
    prog.intervals = fold_intervals(policy);

    auto& out = prog.insns;
    out.reserve(prog.intervals.size() * 4 + 8);

    // prologue: arch guard first. a filter that checks syscall numbers without
    // pinning the arch is exploitable on any machine with more than one syscall
    // convention, so this is not optional.
    out.push_back(ld_abs(kOffArch));
    out.push_back(jeq(arch, 1, 0));
    out.push_back(ret(kRetKillProcess));
    out.push_back(ld_abs(kOffNr));

    if (arch == kAuditArchX86_64) {
        // reject the x32 range outright rather than trying to reason about it.
        out.push_back(jge(kX32SyscallBit, 0, 1));
        out.push_back(ret(kRetKillProcess));
    }

    TreeEmitter emitter{prog.intervals, prog.default_ret};
    emitter.emit(out);
    prog.tree_depth = emitter.depth();

    // classic BPF programs are capped at 4096 instructions by the kernel.
    if (out.size() > 4096)
        return std::unexpected(Error{Errc::too_many_rules, "seccomp: program too large"});

    return prog;
}

std::uint32_t evaluate(const Program& prog, std::uint32_t nr, std::uint32_t arch) {
    // minimal classic-BPF interpreter over struct seccomp_data. only the opcodes
    // we emit are handled; anything else means the emitter changed without the
    // interpreter, so we fail loud instead of guessing.
    std::uint32_t acc = 0;
    std::size_t pc = 0;
    for (std::size_t steps = 0; steps < 100000 && pc < prog.insns.size(); ++steps) {
        const Insn& in = prog.insns[pc];
        std::uint16_t cls = in.code & 0x07;
        if (cls == kLd) {
            acc = (in.k == kOffArch) ? arch : nr;
            ++pc;
        } else if (cls == kRet) {
            return in.k;
        } else if (cls == kJmp) {
            std::uint16_t op = in.code & 0xf0;
            if (op == kJa) {
                pc += 1 + in.k;
            } else {
                bool taken = (op == kJeq)   ? (acc == in.k)
                             : (op == kJgt) ? (acc > in.k)
                             : (op == kJge) ? (acc >= in.k)
                                            : false;
                pc += 1 + (taken ? in.jt : in.jf);
            }
        } else {
            break;
        }
    }
    return kRetKillProcess;  // fell off the end: treat as deny
}

}  // namespace clay::bpf
