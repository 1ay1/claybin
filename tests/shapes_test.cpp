// the shapes are the cross-platform story made concrete: a shape whose mount
// plan is same-path-only compiles to a real sandbox on a host with no mount
// namespaces, and one that remaps paths is refused there. these tests pin that
// distinction, because it is the whole claim.

#include "harness.hpp"

#include "claybin/plan/compile.hpp"
#include "claybin/policy/shapes.hpp"

using namespace clay;
using namespace clay::test;

int main() {
    // a host with every wall EXCEPT mount namespaces: windows and macOS in
    // spirit, and a locked-down linux in practice.
    HostCapabilities mountless = HostCapabilities::modern_linux();
    mountless.mount_namespaces = false;

    const HostCapabilities full = HostCapabilities::modern_linux();

    // -- portable shapes: exact on both hosts ------------------------------
    struct Case {
        const char* name;
        Policy<Sealed> policy;
    };

    auto portable = [&](const char* name, Policy<Draft> d) {
        auto s = std::move(d).seal();
        // exactly expressible without mounts
        CHECK(s.data().mounts.fidelity() == Fidelity::exact);
        CHECK(s.data().mounts.is_portable());

        // compiles on linux, and builds a real tree
        auto on_linux = compile(s, full);
        CHECK(on_linux.has_value());
        if (on_linux) {
            CHECK(on_linux->plan.has(OpCode::pivot_root));
            CHECK(on_linux->plan.has(OpCode::landlock_enforce));
            CHECK(on_linux->fidelity == Fidelity::exact);
        }

        // AND compiles without mounts, with the access wall standing in
        auto without = compile(s, mountless);
        if (!without)
            std::fprintf(stderr, "  [%s] mountless compile failed: %.*s\n", name,
                         static_cast<int>(without.error().mechanism.size()),
                         without.error().mechanism.data());
        CHECK(without.has_value());
        if (without) {
            CHECK(!without->plan.has(OpCode::pivot_root));       // no tree
            CHECK(without->plan.has(OpCode::landlock_enforce));  // but still walled
            CHECK(without->guarantees.strength(CapId::fs_read) == Enforcement::strong);
            CHECK(without->fidelity == Fidelity::exact);
        }
    };

    portable("system_ro", shapes::system_ro().syscall_profile(profiles::base()));
    portable("builder", shapes::builder("/work"));
    portable("strict", shapes::strict());

    // -- app_container REMAPS, so it is linux-only by construction ---------
    {
        auto s = shapes::app_container("/opt/app", "/var/data").seal();
        std::vector<FidelityNote> notes;
        CHECK(s.data().mounts.fidelity(&notes) == Fidelity::impossible);
        CHECK(!s.data().mounts.is_portable());
        CHECK(!notes.empty());

        // on linux it works
        auto on_linux = compile(s, full);
        CHECK(on_linux.has_value());
        if (on_linux) CHECK(on_linux->plan.has(OpCode::pivot_root));

        // without mounts it must REFUSE, not silently give you less
        auto without = compile(s, mountless);
        CHECK(!without.has_value());
        CHECK(without.error().code == Errc::unsupported);
    }

    // -- the shapes grant what they claim and nothing more -----------------
    {
        auto s = shapes::builder("/work").seal();
        FsAuthority fs = s.data().mounts.implied_authority();
        // the workspace is writable
        CHECK(fs.effective("/work").subsumes(FileRights::write()));
        CHECK(fs.effective("/work/sub/deep.c").subsumes(FileRights::write()));
        // the system is readable but NOT writable
        CHECK(fs.effective("/usr/lib").subsumes(FileRights::read()));
        CHECK(!fs.effective("/usr/lib").subsumes(FileRights::write()));
        // and nothing else is reachable at all
        CHECK(fs.effective("/home/ayush/.ssh/id_rsa").is_nothing());
        CHECK(fs.effective("/etc/shadow").is_nothing());
        CHECK(fs.effective("/var").is_nothing());
    }

    // -- strict() really is stricter than builder() ------------------------
    {
        auto strict = shapes::strict().seal();
        auto builder = shapes::builder("/work").seal();
        // strict grants no writable path anywhere the builder has one
        CHECK(strict.data().mounts.implied_authority().effective("/work").is_nothing());
        CHECK(builder.data().mounts.implied_authority()
                  .effective("/work")
                  .subsumes(FileRights::write()));
        // and strict has no fork/exec beyond the base profile
        CHECK(strict.data().syscalls.action_for(57 /* fork */) != SysAction::allow);
    }

    return finish("shapes_test");
}
