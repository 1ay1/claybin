// claybin: filesystem authority as a lattice over a path tree.
//
// a grant maps a path prefix to a set of rights, inherited by the whole subtree
// unless a more specific grant overrides it. "most specific wins" matches
// landlock's hierarchy semantics and, crucially, lets a child grant carry FEWER
// rights than its parent -- a hole punched in an otherwise-open subtree.
//
// the hard part is meet. we need a finite grant set C with
//
//     effective_C(p) = effective_A(p) & effective_B(p)   for every path p
//
// that is exact, not approximate. the trick: effective_X is a step function that
// can only change at a grant boundary of X, so evaluating the pointwise meet at
// the union of both boundary sets captures it everywhere. then we normalize away
// grants that say nothing their parent did not already say.
#pragma once

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

#include "claybin/core/lattice.hpp"

namespace clay {

struct FileRightsTag {};

// rights are a flag lattice; meet is intersection.
class FileRights : public Flags<FileRightsTag, std::uint32_t> {
    using Base = Flags<FileRightsTag, std::uint32_t>;

  public:
    using Base::Base;
    constexpr FileRights(Base b) : Base(b) {}

    // deliberately finer-grained than read/write: these map near-1:1 onto
    // landlock access bits so the backend does not have to guess intent, and
    // coarser backends can fold them.
    static constexpr std::uint32_t kReadFile = 1u << 0;
    static constexpr std::uint32_t kReadDir = 1u << 1;
    static constexpr std::uint32_t kWriteFile = 1u << 2;
    static constexpr std::uint32_t kExecute = 1u << 3;
    static constexpr std::uint32_t kCreateFile = 1u << 4;
    static constexpr std::uint32_t kCreateDir = 1u << 5;
    static constexpr std::uint32_t kRemoveFile = 1u << 6;
    static constexpr std::uint32_t kRemoveDir = 1u << 7;
    static constexpr std::uint32_t kMakeSym = 1u << 8;
    static constexpr std::uint32_t kMakeSpecial = 1u << 9;  // fifo/sock/block/char
    static constexpr std::uint32_t kRename = 1u << 10;
    static constexpr std::uint32_t kTruncate = 1u << 11;
    static constexpr std::uint32_t kIoctlDev = 1u << 12;

    static constexpr FileRights read() { return FileRights{kReadFile | kReadDir}; }
    static constexpr FileRights exec() { return FileRights{kExecute | kReadFile | kReadDir}; }
    static constexpr FileRights write() {
        return FileRights{kReadFile | kReadDir | kWriteFile | kCreateFile | kCreateDir |
                          kRemoveFile | kRemoveDir | kRename | kTruncate};
    }
    static constexpr FileRights all() {
        return FileRights{write().bits() | kExecute | kMakeSym | kMakeSpecial | kIoctlDev};
    }

    static constexpr FileRights nothing() { return FileRights{Base::nothing()}; }
    static constexpr FileRights everything() { return FileRights{all()}; }
    constexpr FileRights meet(FileRights o) const { return FileRights{Base::meet(o)}; }
};

// ---------------------------------------------------------------------------
// path helpers. lexical only -- no syscalls, no symlink resolution. resolution
// is the backend's job and happens against fds, not strings.
// ---------------------------------------------------------------------------

namespace path {

// lexical normalization: collapse duplicate slashes, drop "." and trailing
// slashes, resolve ".." against what we have. always absolute, always canonical
// in shape, so prefix comparison is sound.
inline std::string normalize(std::string_view in) {
    std::vector<std::string_view> parts;
    std::size_t i = 0;
    while (i < in.size()) {
        while (i < in.size() && in[i] == '/') ++i;
        std::size_t start = i;
        while (i < in.size() && in[i] != '/') ++i;
        if (start == i) break;
        std::string_view seg = in.substr(start, i - start);
        if (seg == ".") continue;
        if (seg == "..") {
            if (!parts.empty()) parts.pop_back();
            continue;
        }
        parts.push_back(seg);
    }
    if (parts.empty()) return "/";
    std::string out;
    for (auto seg : parts) {
        out.push_back('/');
        out.append(seg);
    }
    return out;
}

// component-aware prefix test. "/usr" covers "/usr/lib" but never "/usrx".
// both inputs must already be normalized.
inline bool covers(std::string_view ancestor, std::string_view p) {
    if (ancestor == "/") return true;
    if (p.size() < ancestor.size()) return false;
    if (p.substr(0, ancestor.size()) != ancestor) return false;
    return p.size() == ancestor.size() || p[ancestor.size()] == '/';
}

}  // namespace path

// ---------------------------------------------------------------------------
// FsAuthority
// ---------------------------------------------------------------------------

struct FsGrant {
    std::string path;  // normalized, absolute
    FileRights rights;

    friend bool operator==(const FsGrant&, const FsGrant&) = default;
};

class FsAuthority {
  public:
    FsAuthority() = default;

    static FsAuthority nothing() { return FsAuthority{}; }

    // top is "/" with every right. note this is top *of the lattice*, not a
    // recommendation; no builder hands it out by default.
    static FsAuthority everything() {
        FsAuthority a;
        a.grants_.push_back({"/", FileRights::all()});
        return a;
    }

    // grant is a join and therefore only available while building a Draft. it
    // is not part of the composition api.
    FsAuthority& grant(std::string_view p, FileRights r) {
        std::string norm = path::normalize(p);
        for (auto& g : grants_) {
            if (g.path == norm) {
                g.rights = FileRights{g.rights.unsafe_join(r)};
                return *this;
            }
        }
        grants_.push_back({std::move(norm), r});
        sort_();
        return *this;
    }

    // punch a hole: an explicit sub-grant with fewer rights than its ancestor.
    FsAuthority& restrict_to(std::string_view p, FileRights r) {
        std::string norm = path::normalize(p);
        for (auto& g : grants_) {
            if (g.path == norm) {
                g.rights = r;
                return *this;
            }
        }
        grants_.push_back({std::move(norm), r});
        sort_();
        return *this;
    }

    FsAuthority& deny(std::string_view p) { return restrict_to(p, FileRights::nothing()); }

    // what the subtree at `p` is actually allowed to do: the rights of the most
    // specific grant covering it.
    FileRights effective(std::string_view p) const {
        std::string norm = path::normalize(p);
        FileRights best = FileRights::nothing();
        std::size_t best_len = 0;
        bool found = false;
        for (const auto& g : grants_) {
            if (!path::covers(g.path, norm)) continue;
            std::size_t len = g.path == "/" ? 0 : g.path.size();
            if (!found || len >= best_len) {
                best = g.rights;
                best_len = len;
                found = true;
            }
        }
        return best;
    }

    // exact pointwise intersection (see the header comment for why evaluating at
    // the union of boundaries is sufficient).
    FsAuthority meet(const FsAuthority& o) const {
        FsAuthority out;
        out.grants_.reserve(grants_.size() + o.grants_.size());
        auto add = [&](const std::string& p) {
            for (const auto& g : out.grants_)
                if (g.path == p) return;
            out.grants_.push_back({p, effective(p).meet(o.effective(p))});
        };
        for (const auto& g : grants_) add(g.path);
        for (const auto& g : o.grants_) add(g.path);
        out.sort_();
        out.normalize();
        return out;
    }

    bool subsumes(const FsAuthority& o) const {
        // a >= b iff at every boundary of either side a permits everything b does.
        // between boundaries both are constant, so boundaries are exhaustive.
        auto check = [&](const std::string& p) {
            return effective(p).subsumes(o.effective(p));
        };
        for (const auto& g : grants_)
            if (!check(g.path)) return false;
        for (const auto& g : o.grants_)
            if (!check(g.path)) return false;
        return true;
    }

    // is this authority EMPTY -- i.e. did the caller say nothing at all?
    //
    // NOT "does it grant nothing". A policy made only of denials grants
    // nothing and is very much not empty: it is the caller saying "whatever
    // the mounts imply, not THAT path". compile() asks this question to decide
    // whether the mount-implied authority should REPLACE the explicit one, so
    // conflating the two silently discarded every deny.
    //
    // that was a real bug, found by agentty masking ~/.aws under a
    // deliberately permissive scope: with only `.deny()` calls the authority
    // reported nothing, the implied grants replaced it wholesale, and the
    // credentials stayed readable. the mask looked applied and enforced
    // nothing.
    bool is_nothing() const { return grants_.empty(); }

    // does this authority GRANT anything? the other half of the question
    // above, kept separate so a caller has to pick which one it meant.
    bool grants_nothing() const {
        for (const auto& g : grants_)
            if (!g.rights.is_nothing()) return false;
        return true;
    }

    // drop grants that restate what an ancestor already implies. keeps the
    // compiled ruleset small, which directly shrinks the landlock ruleset and
    // the per-spawn setup cost.
    void normalize() {
        sort_();
        std::vector<FsGrant> kept;
        kept.reserve(grants_.size());
        for (const auto& g : grants_) {
            FileRights inherited = FileRights::nothing();
            std::size_t best_len = 0;
            bool found = false;
            for (const auto& a : kept) {
                if (a.path == g.path) continue;
                if (!path::covers(a.path, g.path)) continue;
                std::size_t len = a.path == "/" ? 0 : a.path.size();
                if (!found || len >= best_len) {
                    inherited = a.rights;
                    best_len = len;
                    found = true;
                }
            }
            if (found && inherited == g.rights) continue;   // redundant
            // a denial with no EXPLICIT ancestor grant used to be dropped here
            // as a no-op. it is not: compile() intersects this authority with
            // the one the MOUNTS imply, and that happens after normalize(), so
            // a deny on a path some later bind covers is doing real work.
            //
            // dropping it is how agentty's credential mask enforced nothing --
            // `.deny("~/.aws")` with no matching `.grant()` vanished at seal(),
            // and ~/.aws stayed readable through the $HOME bind. a rule that
            // disappears between being written and being compiled is the worst
            // shape a security control can have, because the policy still
            // reads correct.
            //
            // so a denial is only redundant against an ancestor that is ALSO a
            // denial, which the `inherited == g.rights` line above already
            // covers.
            kept.push_back(g);
        }
        grants_ = std::move(kept);
    }

    const std::vector<FsGrant>& grants() const { return grants_; }

    friend bool operator==(const FsAuthority& a, const FsAuthority& b) {
        // structural equality would make the lattice laws fail for equivalent-
        // but-differently-spelled policies, so compare semantically: agree at
        // every boundary of either side.
        for (const auto& g : a.grants_)
            if (a.effective(g.path) != b.effective(g.path)) return false;
        for (const auto& g : b.grants_)
            if (a.effective(g.path) != b.effective(g.path)) return false;
        return true;
    }

  private:
    void sort_() {
        // shallow-to-deep, so ancestors are visited before descendants.
        std::sort(grants_.begin(), grants_.end(), [](const FsGrant& x, const FsGrant& y) {
            if (x.path.size() != y.path.size()) return x.path.size() < y.path.size();
            return x.path < y.path;
        });
    }

    std::vector<FsGrant> grants_;
};

static_assert(Lattice<FileRights>);
static_assert(Lattice<FsAuthority>);

}  // namespace clay
