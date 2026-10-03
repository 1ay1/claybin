// a MountPlan is a free structure with two interpretations:
//
//   to_tree(plan)       what the filesystem looks like   -- linux only
//   to_authority(plan)  what may be accessed             -- everywhere
//
// the whole cross-platform story rests on the second being SOUND with respect
// to the first: it must never grant a path the tree would not have shown. that
// is a property, so it gets property-tested rather than asserted in a comment.

#include "harness.hpp"

#include "claybin/plan/compile.hpp"
#include "claybin/policy/mounts.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

namespace {

// the paths a generated plan can mention. a small closed set, so the soundness
// check can enumerate every path that could possibly be affected.
constexpr const char* kPaths[] = {"/",    "/usr",  "/usr/lib", "/usr/bin", "/etc",
                                  "/tmp", "/home", "/home/a",  "/work",    "/work/sub"};
constexpr std::size_t kPathCount = sizeof(kPaths) / sizeof(kPaths[0]);

// would the constructed TREE make `p` reachable at all? a path is visible only
// if some mount covers it -- that is the mount model's whole claim.
//
// the switch names EVERY MountKind on purpose, with no default. this function
// is the soundness oracle: a kind that falls through silently reads as "not
// visible", so the oracle would quietly stop checking the very mount type
// someone just added. -Wswitch turning that into a build error is the point.
// (seven kinds were falling through before this -- mask, file, bind_data,
// bind_data_ro and the three overlays -- all of which DO make a path visible.)
bool visible_in_tree(const MountPlan& plan, std::string_view p) {
    std::string norm = path::normalize(p);
    for (const auto& m : plan.mounts()) {
        switch (m.kind) {
            // content at `dest`: the guest can name it and read something.
            case MountKind::bind:
            case MountKind::bind_ro:
            case MountKind::bind_dev:
            case MountKind::tmpfs:
            case MountKind::proc:
            case MountKind::devtmpfs:
            case MountKind::mqueue:
            // data written from the plan itself, and overlays: all of these
            // put a real, nameable object at `dest` too.
            case MountKind::file:
            case MountKind::bind_data:
            case MountKind::bind_data_ro:
            case MountKind::overlay:
            case MountKind::ro_overlay:
            case MountKind::tmp_overlay:
            // mask is VISIBLE, and this is the subtle one. it does not deny the
            // path -- landlock cannot express a deny under a grant at all -- it
            // replaces it with an empty tmpfs or an empty file. so the guest can
            // still name it and gets emptiness, which is reachable-but-useless,
            // not unreachable. treating it as invisible would let the oracle
            // pass a plan that leaks a path it believed was gone.
            case MountKind::mask:
                if (path::covers(path::normalize(m.dest), norm)) return true;
                break;
            case MountKind::symlink:
            case MountKind::dir:
                break;  // structure, not content
        }
    }
    return false;
}

MountPlan gen_plan(Rng& r, bool same_path_only) {
    MountPlan p;
    std::uint32_t n = r.below(5);
    for (std::uint32_t i = 0; i < n; ++i) {
        const char* src = kPaths[r.below(kPathCount)];
        const char* dst = same_path_only ? src : kPaths[r.below(kPathCount)];
        switch (r.below(5)) {
            case 0: p.bind_ro(src, dst); break;
            case 1: p.bind(src, dst); break;
            case 2: p.tmpfs(dst); break;
            case 3: p.proc(dst); break;
            default: p.dev(dst); break;
        }
    }
    return p;
}

}  // namespace

int main() {
    // -- SOUNDNESS: the access interpretation never over-grants ------------
    // for every random plan and every path, if the authority fold grants
    // anything at all then the tree must have made that path visible. a
    // violation here is a real privilege bug on a mountless backend.
    {
        Rng r{0x600D5EEDull};
        for (int i = 0; i < 500; ++i) {
            MountPlan plan = gen_plan(r, i % 2 == 0);
            FsAuthority fs = plan.implied_authority();
            for (const char* p : kPaths) {
                if (fs.effective(p).is_nothing()) continue;
                if (!visible_in_tree(plan, p)) {
                    std::fprintf(stderr, "  UNSOUND: %s granted but not visible\n", p);
                    CHECK(false);
                }
            }
        }
        ++g_checks;
    }

    // -- a read-only bind must not imply write -----------------------------
    {
        MountPlan p;
        p.bind_ro("/usr", "/usr");
        FsAuthority fs = p.implied_authority();
        CHECK(fs.effective("/usr").subsumes(FileRights::read()));
        CHECK(!fs.effective("/usr").subsumes(FileRights::write()));
        // and it must say nothing at all about a path it never mounted
        CHECK(fs.effective("/etc").is_nothing());
        CHECK(fs.effective("/home").is_nothing());
    }

    // -- fidelity: same-path binds are exactly expressible ------------------
    {
        MountPlan p;
        p.bind_ro("/usr", "/usr").bind("/work", "/work");
        CHECK(p.fidelity() == Fidelity::exact);
        CHECK(p.is_portable());
    }

    // -- fidelity: a REMAP is the thing access control cannot do ------------
    {
        MountPlan p;
        p.bind_ro("/usr", "/usr").bind("/home/a", "/work");  // renamed
        std::vector<FidelityNote> notes;
        CHECK(p.fidelity(&notes) == Fidelity::impossible);
        CHECK(!p.is_portable());
        CHECK(!notes.empty());
        // the note must point at the offending mount, not just say "no"
        if (!notes.empty()) CHECK(notes.front().index == 1);
    }

    // -- fidelity: a tmpfs is weaker but still sound ------------------------
    {
        MountPlan p;
        p.bind_ro("/usr", "/usr").tmpfs("/tmp");
        CHECK(p.fidelity() == Fidelity::approximate);
        CHECK(p.is_portable());
    }

    // -- fidelity is a meet: the weakest mount decides ----------------------
    {
        MountPlan p;
        p.bind_ro("/usr", "/usr");        // exact
        p.tmpfs("/tmp");                  // approximate
        CHECK(p.fidelity() == Fidelity::approximate);
        p.bind("/home/a", "/work");       // impossible
        CHECK(p.fidelity() == Fidelity::impossible);
        // and it is order-independent, like any meet
        MountPlan q;
        q.bind("/home/a", "/work");
        q.tmpfs("/tmp");
        q.bind_ro("/usr", "/usr");
        CHECK(q.fidelity() == Fidelity::impossible);
    }

    // -- compile REFUSES rather than silently dropping mounts ---------------
    {
        HostCapabilities mountless = HostCapabilities::modern_linux();
        mountless.mount_namespaces = false;

        // a remapping plan cannot be approximated, so this must fail
        auto remap = Policy<Draft>{}
                         .bind("/home/a", "/work")
                         .syscall_profile(profiles::compiler())
                         .seal();
        auto c1 = compile(remap, mountless);
        CHECK(!c1.has_value());
        CHECK(c1.error().code == Errc::unsupported);

        // a same-path plan CAN be, and compiles with landlock standing in
        auto same = Policy<Draft>{}
                        .ro_bind("/usr", "/usr")
                        .syscall_profile(profiles::compiler())
                        .seal();
        auto c2 = compile(same, mountless);
        CHECK(c2.has_value());
        if (c2) {
            CHECK(c2->fidelity == Fidelity::exact);
            // no tree was built, but the access wall is still there
            CHECK(!c2->plan.has(OpCode::pivot_root));
            CHECK(c2->plan.has(OpCode::landlock_enforce));
            CHECK(c2->guarantees.strength(CapId::fs_read) == Enforcement::strong);
        }
    }

    // -- on a real linux host, BOTH walls go in ----------------------------
    {
        auto pol = Policy<Draft>{}
                       .ro_bind("/usr", "/usr")
                       .tmpfs("/tmp")
                       .syscall_profile(profiles::compiler())
                       .seal();
        auto c = compile(pol, HostCapabilities::modern_linux());
        CHECK(c.has_value());
        if (c) {
            CHECK(c->fidelity == Fidelity::exact);
            CHECK(c->plan.has(OpCode::pivot_root));      // the tree
            CHECK(c->plan.has(OpCode::landlock_enforce)); // and the access wall
        }
    }

    // -- the two interpretations agree on what is granted ------------------
    // whatever landlock ends up allowing must be a subset of what the tree
    // makes visible. this is the linux-side version of the soundness property.
    {
        Rng r{0xA11Eull};
        for (int i = 0; i < 200; ++i) {
            MountPlan plan = gen_plan(r, true);
            if (plan.mounts().empty()) continue;
            FsAuthority implied = plan.implied_authority();
            for (const char* p : kPaths) {
                if (implied.effective(p).is_nothing()) continue;
                CHECK(visible_in_tree(plan, p));
            }
        }
    }

    // -- overlays are IMPOSSIBLE to approximate ----------------------------
    // an overlay merges several directories into one view. that is a new
    // namespace, not a restriction of an existing one, so there is no host path
    // whose contents are the merged view and no access-control system can
    // synthesize one. `impossible`, not `approximate`.
    {
        MountPlan p;
        p.tmp_overlay({"/usr", "/etc"}, "/data");
        std::vector<FidelityNote> notes;
        CHECK(p.fidelity(&notes) == Fidelity::impossible);
        CHECK(!p.is_portable());
        CHECK(!notes.empty());
    }
    {
        MountPlan p;
        p.ro_overlay({"/usr", "/etc"}, "/data");
        CHECK(p.fidelity() == Fidelity::impossible);
    }
    {
        MountPlan p;
        p.overlay({"/usr"}, "/tmp/up", "/tmp/wk", "/data");
        CHECK(p.fidelity() == Fidelity::impossible);
    }

    // -- but the implied authority is still SOUND --------------------------
    // even though we cannot reproduce the view, the grant we derive must not
    // over-promise: a writable overlay is writable at its dest and says nothing
    // about anything else.
    {
        MountPlan p;
        p.tmp_overlay({"/usr", "/etc"}, "/data");
        FsAuthority fs = p.implied_authority();
        CHECK(fs.effective("/data").subsumes(FileRights::write()));
        CHECK(fs.effective("/data/sub/deep").subsumes(FileRights::write()));
        // the LOWER layers are not granted at their host paths: the guest sees
        // them only through /data, and granting /usr would be a real widening.
        CHECK(fs.effective("/usr").is_nothing());
        CHECK(fs.effective("/etc").is_nothing());
    }
    {
        // a read-only overlay must not imply write
        MountPlan p;
        p.ro_overlay({"/usr", "/etc"}, "/data");
        FsAuthority fs = p.implied_authority();
        CHECK(fs.effective("/data").subsumes(FileRights::read()));
        CHECK(!fs.effective("/data").subsumes(FileRights::write()));
    }

    // -- an overlay makes a whole plan unportable --------------------------
    // fidelity is a meet, so one overlay is enough to sink an otherwise exact
    // plan. that is the point: compile() then refuses on a mountless host
    // rather than handing back something that is not an overlay at all.
    {
        MountPlan p;
        p.bind_ro("/usr", "/usr");          // exact on its own
        CHECK(p.fidelity() == Fidelity::exact);
        p.tmp_overlay({"/etc"}, "/data");   // and now it is not
        CHECK(p.fidelity() == Fidelity::impossible);
    }

    return finish("mount_algebra_test");
}
