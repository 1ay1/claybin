// a live check of the macOS apply path. unlike macos_backend_test (pure
// translation, runs everywhere) this one actually ENTERS a seatbelt sandbox
// and asserts the walls hold, so it only means anything on a mac.
//
// it is a separate binary rather than more cases in the backend test because
// it needs to fork real children and read their exit codes -- and because a
// test that silently skips on every CI runner should be obviously the one
// doing the skipping.
#include "harness.hpp"

#include "claybin/macos/backend.hpp"
#include "claybin/policy/shapes.hpp"

#if defined(__APPLE__)
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace clay;
using namespace clay::test;

#if defined(__APPLE__)
namespace {

// run `/bin/sh -c cmd` inside the compiled sandbox, return its exit status.
// -1 means the spawn itself failed.
int run_in(const macos::Compiled& c, const char* cmd) {
    const char* argv[] = {"/bin/sh", "-c", cmd, nullptr};
    macos::SpawnRequest req;
    req.program = "/bin/sh";
    req.argv = argv;
    // discard the guest's output: a denial prints to stderr and would make the
    // test log look like a failure when it is in fact the sandbox working.
    req.stdout_fd = macos::SpawnRequest::kDevNull;
    req.stderr_fd = macos::SpawnRequest::kDevNull;

    auto s = macos::spawn(c, req);
    if (!s) return -1;

    int status = 0;
    while (::waitpid(s->pid, &status, 0) < 0) {
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

}  // namespace
#endif

int main() {
#if !defined(__APPLE__)
    return skip("macos_live_check", "not macOS");
#else
    const auto host = macos::probe_host();
    if (!host.seatbelt) return skip("macos_live_check", "seatbelt unavailable");

    // a policy that can run a shell: read the system, write only to /tmp, no
    // network. fork and exec are allowed, because /bin/sh cannot run a command
    // without them -- which is itself worth asserting, since a sandbox that
    // forbids them looks identical to a broken one.
    auto pol = Policy<Draft>{}
                   .read("/usr")
                   .read("/bin")
                   .read("/System")
                   .read("/private/var/select")
                   .execute("/bin")
                   .execute("/usr/bin")
                   .read_write("/private/tmp")
                   .allow_fork()
                   .allow_exec()
                   .seal();

    auto c = macos::compile(pol, host);
    CHECK(c.has_value());
    if (!c) return finish("macos_live_check");

    // -- the sandbox does not break the program ----------------------------
    // first, and most important: a sandbox that denies everything passes every
    // "is it blocked" test and is still useless. the guest must RUN.
    CHECK_EQ(run_in(*c, "exit 0"), 0);

    // -- the write wall holds ----------------------------------------------
    CHECK_EQ(run_in(*c, "echo hi > /private/tmp/claybin_live_ok"), 0);
    // writing outside the grant must fail. /etc is readable, not writable.
    CHECK(run_in(*c, "echo no > /etc/claybin_should_not_exist") != 0);
    // and the denied write must not have happened
    CHECK(::access("/etc/claybin_should_not_exist", F_OK) != 0);
    ::unlink("/private/tmp/claybin_live_ok");

    // -- the read wall holds -----------------------------------------------
    // the guest was never granted the user's home directory.
    {
        auto ro = Policy<Draft>{}
                      .read("/usr")
                      .read("/bin")
                      .read("/System")
                      .execute("/bin")
                      .execute("/usr/bin")
                      .allow_fork()
                      .allow_exec()
                      .seal();
        auto rc = macos::compile(ro, host);
        CHECK(rc.has_value());
        if (rc) CHECK(run_in(*rc, "ls ~ > /dev/null 2>&1") != 0);
    }

    // -- a failed sandbox must never run the program -----------------------
    // the most important property in the whole backend: if sandbox_init fails,
    // the child must die rather than exec unconfined. feed it a profile the
    // kernel will reject and assert we get the setup-failure code, NOT the
    // exit code of a program that ran.
    //
    // the kernel prints its own rejection message to stderr before we ever see
    // the error, so this case is run with stderr pointed at /dev/null -- a
    // passing test that dumps a sandbox error into the log reads as a failure
    // to everyone who sees it afterwards.
    {
        macos::Compiled broken = *c;
        broken.profile = "(version 1) (this-is-not-a-real-sbpl-form";
        const int rc = run_in(broken, "exit 7");
        CHECK(rc != 7);  // the guest must NOT have run
        CHECK_EQ(rc, macos::kExitPlanFailed);
    }

    return finish("macos_live_check");
#endif
}
