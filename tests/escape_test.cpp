// the escape suite. this is the test that decides whether any of the rest of
// the library means anything: it spawns real processes inside a real sandbox
// and tries to get out.
//
// each case runs a tiny helper program (this same binary, re-execed with an
// argument) under a policy, and asserts the outcome. a sandbox that "seems to
// work" is worthless; the point is a list of specific attempts and what
// happened to each.

#include "harness.hpp"

#include <cstdlib>
#include <cstring>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

#if defined(__linux__)

namespace {

// ---- the attacker side. re-exec of this binary with "attack <name>". ----
// each returns 0 if the escape SUCCEEDED, which means the test must see a
// nonzero exit for the sandbox to be considered working.

int attack_read(const char* path) {
    int fd = ::open(path, O_RDONLY);
    if (fd < 0) return 1;
    char b[1];
    ssize_t n = ::read(fd, b, 1);
    ::close(fd);
    return n > 0 ? 0 : 1;
}

int attack_write(const char* path) {
    int fd = ::open(path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) return 1;
    ::close(fd);
    return 0;
}

int run_attack(const char* name) {
    if (std::strcmp(name, "read_etc_shadow") == 0) return attack_read("/etc/shadow");
    if (std::strcmp(name, "read_ssh_key") == 0) {
        const char* home = ::getenv("REAL_HOME");
        if (!home) return 1;
        char buf[512];
        std::snprintf(buf, sizeof buf, "%s/.ssh/id_rsa", home);
        return attack_read(buf);
    }
    if (std::strcmp(name, "write_tmp") == 0) return attack_write("/tmp/clay_escape_probe");
    if (std::strcmp(name, "read_workspace") == 0) return attack_read("/usr/lib/os-release");
    if (std::strcmp(name, "ptrace") == 0) {
        // killed by seccomp if the filter works
        long rc = ::syscall(101 /* ptrace */, 0, 0, 0, 0);
        return rc == 0 ? 0 : 1;
    }
    if (std::strcmp(name, "unshare") == 0) {
        long rc = ::syscall(272 /* unshare */, 0x10000000 /* CLONE_NEWUSER */);
        return rc == 0 ? 0 : 1;
    }
    if (std::strcmp(name, "socket") == 0) {
        long rc = ::syscall(41 /* socket */, 2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
        return rc >= 0 ? 0 : 1;
    }
    if (std::strcmp(name, "ok") == 0) return 42;  // control: proves exec works
    return 3;
}

// ---- the harness side ----

struct Outcome {
    bool spawned{false};
    int status{-1};
    bool exited{false};
    int code{-1};
    bool signalled{false};
    int sig{-1};
    // spawn() now reports child setup failures over a pipe, so a refusal to
    // start is distinguishable from a program that ran and failed.
    bool setup_failed{false};
    Error setup_error{};
};

Outcome run_in_sandbox(const Policy<Sealed>& pol, const char* attack, const char* self) {
    Outcome o;
    auto c = compile(pol, probe_host());
    if (!c) return o;

    char arg0[512];
    std::snprintf(arg0, sizeof arg0, "%s", self);
    const char* argv[] = {arg0, "attack", attack, nullptr};

    char home_env[512];
    const char* home = ::getenv("HOME");
    std::snprintf(home_env, sizeof home_env, "REAL_HOME=%s", home ? home : "/root");
    const char* envp[] = {home_env, nullptr};

    Command cmd{self, argv, envp};
    auto sp = spawn(c->plan, cmd);
    if (!sp) {
        o.setup_failed = true;
        o.setup_error = sp.error();
        return o;
    }

    o.spawned = true;
    int status = 0;
    ::waitpid(sp->pid, &status, 0);
    if (sp->pidfd >= 0) ::close(sp->pidfd);

    o.status = status;
    o.exited = WIFEXITED(status);
    if (o.exited) o.code = WEXITSTATUS(status);
    o.signalled = WIFSIGNALED(status);
    if (o.signalled) o.sig = WTERMSIG(status);
    // spawn() forks a shepherd to enter the pid namespace, and a shepherd
    // cannot re-raise a signal death as a signal death without also dying to
    // it, so it relays 128+signo instead. treat that as a kill, which is what
    // it means.
    if (o.exited && o.code > 128 && o.code < 160) {
        o.signalled = true;
        o.sig = o.code - 128;
    }
    return o;
}

// the escape must have been BLOCKED. a child killed by a signal or exiting
// nonzero counts; a child that never started does NOT, because then we learned
// nothing about the walls.
bool blocked(const Outcome& o) {
    if (o.setup_failed) return false;
    if (!o.spawned) return false;
    if (o.signalled) return true;  // seccomp killed it
    if (o.exited && o.code == kExitPlanFailed) return false;
    return o.exited && o.code != 0;
}

// print why a run did not even start. without this the suite reports a wall of
// identical failures and you cannot tell a blocked escape from a broken test.
void explain(const Outcome& o, const char* label) {
    if (o.setup_failed) {
        std::fprintf(stderr, "  [%s] did not start: %s / %.*s errno=%d\n", label,
                     to_string(o.setup_error.code).data(),
                     static_cast<int>(o.setup_error.mechanism.size()),
                     o.setup_error.mechanism.data(), o.setup_error.sys_errno);
    } else if (o.exited && o.code == kExitPlanFailed) {
        std::fprintf(stderr, "  [%s] sandbox setup failed inside child\n", label);
    }
}

}  // namespace

#endif  // __linux__

int main(int argc, char** argv) {
#if defined(__linux__)
    // attacker mode
    if (argc >= 3 && std::strcmp(argv[1], "attack") == 0) return run_attack(argv[2]);



    // the test binary does not live under /usr, so the policy has to grant exec
    // on wherever it actually is. resolving this at runtime rather than
    // hardcoding a path is what makes the suite work from any build dir.
    static char self_real[4096];
    ssize_t sl = ::readlink("/proc/self/exe", self_real, sizeof self_real - 1);
    if (sl <= 0) {
        std::fprintf(stderr, "escape_test: cannot resolve own path\n");
        return 1;
    }
    self_real[sl] = '\0';
    // the directory containing it
    static char self_dir[4096];
    std::snprintf(self_dir, sizeof self_dir, "%s", self_real);
    if (char* slash = std::strrchr(self_dir, '/')) *slash = '\0';

    auto host = probe_host();
    if (host.landlock_abi == 0 || !host.seccomp) {
        std::fprintf(stderr, "skip escape_test: host lacks landlock/seccomp\n");
        return 0;
    }
    // user namespaces too: without them there is no mount namespace to build the
    // tree in, and every case here spawns a real sandbox. this guard was missing
    // and the first CI run failed all 12 checks with a bare errno=13 -- the
    // probe said userns was available because it read sysctls instead of trying
    // a uid_map write.
    if (!host.user_namespaces || !host.mount_namespaces) {
        std::fprintf(stderr, "skip escape_test: no user/mount namespaces\n");
        return 0;
    }

    // the policy under test: read /usr, exec our own binary, nothing else.
    //
    // note the loader grants. a dynamically linked binary is not just the file
    // you exec: the kernel maps ld.so, which then opens libc and friends. on a
    // usr-merged distro /lib64 is a symlink into /usr/lib, but landlock matches
    // on the path the loader actually opens, so both spellings need the grant.
    // getting this wrong looks exactly like "the sandbox is broken" and is the
    // single most common landlock mistake.
    auto make_policy = [&] {
        return Policy<Draft>{}
            .read("/usr")
            .execute("/usr")
            .execute("/lib")
            .execute("/lib64")
            .execute(self_dir)   // so the re-exec of ourselves is allowed
            .workdir("/")
            // compiler() rather than with_filesystem(): spawn() execs into the
            // sandbox, so the filter has to allow execve or it denies our own
            // launch. with_filesystem() is for a process restricting itself.
            .syscall_profile(profiles::compiler())
            .seal();
    };

    // -- control: the sandbox must let a legitimate program run -----------
    {
        auto o = run_in_sandbox(make_policy(), "ok", self_real);
        explain(o, "control");
        CHECK(o.spawned);
        // 42 is the control value: proves apply() ran and execve succeeded
        CHECK(o.exited && o.code == 42);
    }

    // -- filesystem escapes ------------------------------------------------
    {
        auto o = run_in_sandbox(make_policy(), "read_etc_shadow", self_real);
        CHECK(blocked(o));
    }
    {
        auto o = run_in_sandbox(make_policy(), "read_ssh_key", self_real);
        CHECK(blocked(o));
    }
    {
        auto o = run_in_sandbox(make_policy(), "write_tmp", self_real);
        CHECK(blocked(o));
    }

    // -- and the granted path must still WORK. a sandbox that blocks
    // -- everything is trivially "secure" and completely useless.
    {
        auto o = run_in_sandbox(make_policy(), "read_workspace", self_real);
        CHECK(o.spawned);
        CHECK(o.exited && o.code == 0);  // reading /usr is allowed
    }

    // -- syscall escapes ---------------------------------------------------
    {
        auto o = run_in_sandbox(make_policy(), "ptrace", self_real);
        CHECK(blocked(o));
        // and it must be KILLED, not merely denied: the profile says kill for
        // the classic escapes so they are unmistakable in an audit log.
        CHECK(o.signalled);
    }
    {
        auto o = run_in_sandbox(make_policy(), "unshare", self_real);
        CHECK(blocked(o));
        CHECK(o.signalled);
    }

    // -- network -----------------------------------------------------------
    {
        // the policy grants no network, so socket() is not in the allow-list
        auto o = run_in_sandbox(make_policy(), "socket", self_real);
        CHECK(blocked(o));
    }

#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "skip escape_test: linux only\n");
#endif
    return finish("escape_test");
}
