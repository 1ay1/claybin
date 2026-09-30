// path shapes: the matcher, not the rules.
//
// This tests the MECHANISM claybin owns. Which shapes matter is an embedder's
// policy (see agentty's trust-handoff table); what claybin has to get right is
// the matching, and it has a sharp edge in both directions that this pins:
//
//   too loose  a substring test matches ".gitignore" for ".git". a rule that
//              fires on ordinary files gets ignored, which is worse than none.
//   too tight  an exact-name test against a flexible tool is one entry short.
//              Cursor matched `.git` literally and `git --git-dir=.foo` walked
//              past the sandbox (fixed in 3.0.0).
//
// So every case below is either a documented bypass or the false positive that
// would make the feature unusable.
#include "harness.hpp"

#include <array>
#include <span>

#include "claybin/policy/path_shape.hpp"

using namespace clay;
using namespace clay::test;

int main() {
    // -- basename ---------------------------------------------------------
    CHECK_EQ(path::basename("/a/b/c"), std::string_view{"c"});
    CHECK_EQ(path::basename("c"), std::string_view{"c"});
    CHECK_EQ(path::basename("/"), std::string_view{""});
    CHECK_EQ(path::basename(""), std::string_view{""});

    // -- has_component: whole components only -----------------------------
    //
    // The first four are the reason this is not a substring search.
    CHECK(path::has_component("/w/.git/config", ".git"));
    CHECK(!path::has_component("/w/.gitignore", ".git"));
    CHECK(!path::has_component("/w/git", ".git"));
    CHECK(!path::has_component("/w/x.git.bak", ".git"));
    // at any depth, including first and last
    CHECK(path::has_component(".git/config", ".git"));
    CHECK(path::has_component("/w/a/.git", ".git"));
    // a multi-component needle matches as a contiguous run
    CHECK(path::has_component("/w/node_modules/.bin/tsc", "node_modules/.bin"));
    CHECK(!path::has_component("/w/node_modules/tsc", "node_modules/.bin"));
    // and the run has to end on a boundary
    CHECK(!path::has_component("/w/node_modules/.binx/tsc", "node_modules/.bin"));
    // empty needle matches nothing, rather than everything
    CHECK(!path::has_component("/w/a", ""));

    // -- the three match modes --------------------------------------------
    enum Tag : std::uint32_t { kHook = 1, kGit = 2, kCert = 3 };
    static constexpr std::array rules{
        ShapeRule{"hooks.json", kHook, ShapeMatch::Basename},
        ShapeRule{".git", kGit, ShapeMatch::Component},
        ShapeRule{".pem", kCert, ShapeMatch::Suffix},
    };
    const std::span<const ShapeRule> rs{rules};

    auto tag_of = [&](std::string_view p) -> long {
        std::uint32_t t = 0;
        return shape_matches(p, rs, &t) ? static_cast<long>(t) : -1;
    };

    CHECK_EQ(tag_of("/w/.agentty/hooks.json"), 1L);
    CHECK_EQ(tag_of("/w/.git/config"), 2L);
    CHECK_EQ(tag_of("/w/.mygit/../.git/hooks"), 2L);  // renamed dir, real .git
    CHECK_EQ(tag_of("/w/key.pem"), 3L);

    // the false positives that would sink the feature
    CHECK_EQ(tag_of("/w/src/main.cpp"), -1L);
    CHECK_EQ(tag_of("/w/.gitignore"), -1L);
    CHECK_EQ(tag_of("/w/hooks.json.bak"), -1L);  // basename, not prefix
    CHECK_EQ(tag_of("/w/pem"), -1L);             // suffix needs more than itself
    CHECK_EQ(tag_of("/w/.pem"), -1L);            // ditto: base == needle is not a suffix match

    // first match wins, so a caller can order for precedence
    static constexpr std::array ordered{
        ShapeRule{"config", 10, ShapeMatch::Basename},
        ShapeRule{".git", 20, ShapeMatch::Component},
    };
    std::uint32_t t = 0;
    CHECK(shape_matches("/w/.git/config", std::span<const ShapeRule>{ordered}, &t));
    CHECK_EQ(static_cast<long>(t), 10L);  // the basename rule came first

    // no out_tag is allowed: the caller may only want the boolean
    CHECK(shape_matches("/w/.git/config", rs));
    CHECK(!shape_matches("/w/README.md", rs));

    return finish("path_shape_test");
}
