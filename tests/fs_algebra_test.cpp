// path normalization and the "most specific grant wins" hierarchy, which is the
// semantics landlock gives us and the thing path-traversal bugs live in.

#include "harness.hpp"

#include "claybin/policy/filesystem.hpp"

using namespace clay;
using namespace clay::test;

int main() {
    // -- normalization -----------------------------------------------------
    CHECK_EQ(path::normalize("/usr//lib/"), std::string("/usr/lib"));
    CHECK_EQ(path::normalize("/usr/./lib"), std::string("/usr/lib"));
    CHECK_EQ(path::normalize("/usr/lib/../bin"), std::string("/usr/bin"));
    CHECK_EQ(path::normalize("/"), std::string("/"));
    CHECK_EQ(path::normalize(""), std::string("/"));
    CHECK_EQ(path::normalize("/.."), std::string("/"));
    // the classic escape: ".." must never climb above root
    CHECK_EQ(path::normalize("/../../../etc/passwd"), std::string("/etc/passwd"));
    CHECK_EQ(path::normalize("/a/b/../../../../c"), std::string("/c"));

    // -- prefix must be component-aware ------------------------------------
    CHECK(path::covers("/usr", "/usr/lib"));
    CHECK(path::covers("/usr", "/usr"));
    CHECK(path::covers("/", "/anything"));
    // "/usr" must NOT cover "/usrx" -- naive string prefix would say yes
    CHECK(!path::covers("/usr", "/usrx"));
    CHECK(!path::covers("/usr/lib", "/usr"));
    CHECK(!path::covers("/workspace", "/workspace-evil"));

    // -- inheritance -------------------------------------------------------
    {
        FsAuthority fs;
        fs.grant("/usr", FileRights::read());
        CHECK(fs.effective("/usr/lib/libc.so").subsumes(FileRights::read()));
        CHECK(fs.effective("/etc").is_nothing());
        CHECK(fs.effective("/usrx").is_nothing());
    }

    // -- most specific wins, including punching a hole ---------------------
    {
        FsAuthority fs;
        fs.grant("/workspace", FileRights::write());
        fs.deny("/workspace/.git");
        CHECK(fs.effective("/workspace/src/main.cpp").subsumes(FileRights::write()));
        CHECK(fs.effective("/workspace/.git").is_nothing());
        CHECK(fs.effective("/workspace/.git/config").is_nothing());  // hole is inherited
    }

    // a deeper re-grant inside a hole works too
    {
        FsAuthority fs;
        fs.grant("/home", FileRights::read());
        fs.deny("/home/ayush/.ssh");
        fs.restrict_to("/home/ayush/.ssh/known_hosts", FileRights::read());
        CHECK(fs.effective("/home/ayush/.ssh/id_rsa").is_nothing());
        CHECK(fs.effective("/home/ayush/.ssh/known_hosts").subsumes(FileRights::read()));
    }

    // -- meet is intersection, pointwise -----------------------------------
    {
        FsAuthority a, b;
        a.grant("/workspace", FileRights::write());
        a.grant("/usr", FileRights::read());
        b.grant("/workspace", FileRights::read());
        b.grant("/tmp", FileRights::write());

        FsAuthority m = a & b;
        // write & read == read
        CHECK_EQ(m.effective("/workspace"), FileRights::read());
        // only one side granted /usr, so the intersection has nothing
        CHECK(m.effective("/usr").is_nothing());
        CHECK(m.effective("/tmp").is_nothing());
    }

    // -- normalize removes redundancy without changing meaning -------------
    {
        FsAuthority fs;
        fs.grant("/usr", FileRights::read());
        fs.grant("/usr/lib", FileRights::read());   // same as parent: redundant
        fs.grant("/usr/bin", FileRights::exec());   // different: must survive
        auto before_lib = fs.effective("/usr/lib");
        auto before_bin = fs.effective("/usr/bin");
        std::size_t n_before = fs.grants().size();
        fs.normalize();
        CHECK(fs.grants().size() < n_before);
        CHECK_EQ(fs.effective("/usr/lib"), before_lib);
        CHECK_EQ(fs.effective("/usr/bin"), before_bin);
    }

    // -- rights semantics --------------------------------------------------
    CHECK(FileRights::write().subsumes(FileRights::read()));   // write implies read
    CHECK(!FileRights::read().subsumes(FileRights::write()));
    CHECK(FileRights::all().subsumes(FileRights::exec()));
    CHECK(!FileRights::write().subsumes(FileRights::exec()));  // write must NOT imply exec

    return finish("fs_algebra_test");
}
