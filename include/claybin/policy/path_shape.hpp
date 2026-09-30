#pragma once
// claybin: path-shape rules.
//
// A table of "what does this path LOOK like" predicates, matched without
// allocation. The rules are DATA the caller supplies; claybin supplies the
// matching, because getting path matching right is a kernel-adjacent problem
// with a documented vulnerability class attached and no reason for every
// embedder to re-derive it.
//
// ── Why this is a claybin concern and not an embedder's ─────────────────
//
// The mechanism is general: "classify a path by its shape, using whole
// components rather than substrings". The POLICY -- which shapes matter, and
// what to do about them -- is entirely the caller's.
//
// The division matters because the mechanism has a sharp edge in both
// directions, and each side is a real bug somebody shipped:
//
//   too loose  a substring test matches ".gitignore" for ".git" and
//              "configure.ac" for "config". a rule that fires on ordinary
//              files trains the user to ignore it, which is worse than no
//              rule at all.
//   too tight  an exact-name test against a flexible tool is always one entry
//              short. Cursor matched `.git` literally; `git --git-dir=.foo`
//              walked straight past the sandbox (fixed in 3.0.0).
//
// So the matching lives here, next to path::covers and path::normalize, which
// exist for the same reason. What a caller does with a match is its own
// business -- agentty refuses agent-authored writes to host-executed paths;
// something else might just log them.
//
// ── What this is NOT ───────────────────────────────────────────────────
//
// Not enforcement. Nothing here restricts anything; it answers a question
// about a string. A path that matches is still reachable unless the caller
// masks or denies it. Keeping classification separate from enforcement is
// deliberate: the interesting uses (audit, provenance, warn-but-allow) all
// need the answer WITHOUT the restriction.

#include <cstdint>
#include <span>
#include <string_view>

#include "claybin/policy/filesystem.hpp"  // path::basename, path::has_component

namespace clay {

// How a rule's needle is matched against a path.
enum class ShapeMatch : std::uint8_t {
    // The needle must be a whole path COMPONENT, at any depth. ".git" matches
    // "/w/.git/config" and "/w/.mygit/../.git" but never "/w/.gitignore".
    // A needle containing '/' ("node_modules/.bin") matches as a run.
    Component,
    // The needle must be the FINAL component. "tasks.json" matches
    // "/w/.vscode/tasks.json" but not "/w/tasks.json//x".
    Basename,
    // The needle must be a SUFFIX of the final component. ".pem" matches
    // "key.pem". Separate from Basename because a suffix rule cannot be
    // expressed as one and every certificate convention needs it.
    Suffix,
};

// One rule. `tag` is an opaque integer the caller gives meaning to -- claybin
// has no opinion about what a matched path signifies, so it does not model
// one. An enum cast to std::uint32_t is the intended use.
struct ShapeRule {
    std::string_view needle;
    std::uint32_t tag = 0;
    ShapeMatch match = ShapeMatch::Component;
};

// Does any rule match? On a hit, `out_tag` receives the matching rule's tag.
//
// First match wins, so a caller that cares about precedence orders its table.
// No allocation and no normalisation: the caller passes the path it has, which
// keeps this usable on the post-fork side where allocation is unsafe.
[[nodiscard]] inline bool shape_matches(std::string_view p,
                                        std::span<const ShapeRule> rules,
                                        std::uint32_t* out_tag = nullptr) {
    const std::string_view base = path::basename(p);
    for (const auto& r : rules) {
        bool hit = false;
        switch (r.match) {
            case ShapeMatch::Component:
                hit = path::has_component(p, r.needle);
                break;
            case ShapeMatch::Basename:
                hit = base == r.needle;
                break;
            case ShapeMatch::Suffix:
                hit = base.size() > r.needle.size() && base.ends_with(r.needle);
                break;
        }
        if (hit) {
            if (out_tag) *out_tag = r.tag;
            return true;
        }
    }
    return false;
}

}  // namespace clay
