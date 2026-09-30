// The embedder's use case: run a command in a sandbox and capture its output
// over a pipe the CALLER owns, with the caller's own wait/reap.
//
// This is the thing that makes claybin a library rather than a subprocess. If
// the pipe does not survive spawn()'s close sweep, an embedder gets a command
// that runs and produces nothing -- which looks like a broken sandbox rather
// than a missing fd.
#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/profiles.hpp"

#include "harness.hpp"

#include <cstdio>
#include <cstring>
#include <string>

#if defined(__linux__)
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace clay;
using namespace clay::literals;
using namespace clay::test;

#if defined(__linux__)

int main() {
    auto host = probe_host();
    if (!host.user_namespaces || !host.mount_namespaces) {
        std::fprintf(stderr, "skip embed_test: no user/mount namespaces\n");
        return 0;
    }
    const char* cmd = "echo out-line; echo err-line >&2; exit 7";

    auto sealed = Policy<Draft>{}
                      .ro_bind("/usr", "/usr")
                      .bind_try("/lib", "/lib")
                      .bind_try("/lib64", "/lib64")
                      .bind_try("/bin", "/bin")
                      .proc_fs("/proc")
                      .dev_fs("/dev")
                      .tmpfs("/tmp", 64_MB)
                      .workdir("/")
                      .syscall_profile(profiles::compiler())
                      .seal();

    auto c = compile(sealed, host);
    CHECK(c.has_value());
    if (!c) return finish("embed_test");

    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        std::perror("pipe");
        return 1;
    }

    const char* av[] = {"/bin/sh", "-c", cmd, nullptr};
    Command command{"/bin/sh", av, nullptr};
    // stdout AND stderr to the same pipe, stdin from /dev/null -- exactly what
    // a tool runner wants.
    command.stdin_fd = Command::kDevNull;
    command.stdout_fd = pipefd[1];
    command.stderr_fd = pipefd[1];

    auto s = spawn(c->plan, command);
    CHECK(s.has_value());
    if (!s) return finish("embed_test");
    ::close(pipefd[1]);  // parent drops the write end so read() sees EOF

    std::string out;
    char buf[4096];
    for (;;) {
        ssize_t n = ::read(pipefd[0], buf, sizeof buf);
        if (n <= 0) break;
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(pipefd[0]);

    int st = 0;
    ::waitpid(s->pid, &st, 0);
    int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;

    if (s->pidfd >= 0) ::close(s->pidfd);

    // stdout captured
    CHECK(out.find("out-line") != std::string::npos);
    // stderr captured on the SAME pipe
    CHECK(out.find("err-line") != std::string::npos);
    // and the guest's exit code reached the caller, not the helper's
    CHECK_EQ(code, 7);

    return finish("embed_test");
}

#else
int main() {
    std::fprintf(stderr, "skip embed_test: linux only\n");
    return 0;
}
#endif
