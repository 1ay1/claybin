// run the whole attack corpus through a real sandbox and report every outcome.
//
// the value is not the pass count. it is that each line names a specific thing
// an attacker would try, and says what happened -- so a reader can check the
// claim rather than trust it. an escape here is a real vulnerability.

#include "harness.hpp"

#include <cstring>

#if defined(__linux__)
#include <cstddef>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "attacks.hpp"

#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/shapes.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

#if defined(__linux__)
namespace {

struct Outcome {
    bool started{false};
    int code{-1};
    bool signalled{false};
    int sig{0};
    Error err{};
};

Outcome run_attack(const Policy<Sealed>& pol, const char* self, const char* name,
                   bool leak_fd, const char* env_entry = nullptr) {
    Outcome o;
    auto c = compile(pol, probe_host());
    if (!c) {
        o.err = c.error();
        return o;
    }

    const char* argv[] = {self, "attack", name, nullptr};
    // the policy's env list is caller data, not part of the plan -- claybin
    // compiles authority, and it is spawn's caller that decides what execve
    // sees. so an env var the guest should read has to be handed over here.
    const char* envp[] = {env_entry, nullptr};
    Command cmd{self, argv, env_entry ? envp : nullptr};

    // for the inherited-fd case the harness deliberately leaks one, so the
    // attack has something to find. the whole point is that claybin closes it
    // anyway.
    int leaked = -1;
    if (leak_fd) {
        leaked = ::open("/etc/hostname", O_RDONLY);
        if (leaked >= 0 && leaked != 7) {
            ::dup2(leaked, 7);
            ::close(leaked);
            leaked = 7;
        }
    }

    auto sp = spawn_in(c->plan, cmd, c->cgroup);
    if (leaked >= 0) ::close(leaked);
    if (!sp) {
        o.err = sp.error();
        return o;
    }

    o.started = true;
    int st = 0;
    ::waitpid(sp->pid, &st, 0);
    if (sp->pidfd >= 0) ::close(sp->pidfd);
    if (WIFEXITED(st)) o.code = WEXITSTATUS(st);
    if (WIFSIGNALED(st)) {
        o.signalled = true;
        o.sig = WTERMSIG(st);
    }
    // the shepherd relays a signal death as 128+signo
    if (o.code > 128 && o.code < 160) {
        o.signalled = true;
        o.sig = o.code - 128;
    }
    return o;
}

}  // namespace
#endif

int main(int argc, char** argv) {
#if defined(__linux__)
    // attacker mode
    if (argc >= 3 && std::strcmp(argv[1], "attack") == 0) {
        std::size_t n = 0;
        const auto* t = attacks::table(n);
        for (std::size_t i = 0; i < n; ++i)
            if (std::strcmp(t[i].name, argv[2]) == 0) return t[i].run();
        return 3;  // unknown attack name
    }

    static char self[4096];
    ssize_t sl = ::readlink("/proc/self/exe", self, sizeof self - 1);
    if (sl <= 0) return 1;
    self[sl] = '\0';
    static char dir[4096];
    std::snprintf(dir, sizeof dir, "%s", self);
    if (char* s = std::strrchr(dir, '/')) *s = '\0';

    auto host = probe_host();
    if (host.landlock_abi == 0 || !host.seccomp || !host.user_namespaces) {
        std::fprintf(stderr, "skip escape_corpus_test: host lacks landlock/seccomp/userns\n");
        return 0;
    }

    // the policy under attack: a realistic build sandbox. a tree built from
    // binds, one writable workspace, no network, the compiler syscall profile.
    // deliberately NOT the tightest possible policy -- the corpus should pass
    // against something a real caller would actually write.
    auto make = [&] {
        return Policy<Draft>{}
            .ro_bind("/usr", "/usr")
            .bind_try("/lib", "/lib")
            .bind_try("/lib64", "/lib64")
            .bind_try("/bin", "/bin")
            .ro_bind(dir, "/app")
            .tmpfs("/tmp", 64_MB)
            .proc_fs("/proc")
            .dev_fs("/dev")
            .workdir("/")
            .syscall_profile(profiles::compiler())
            .memory(256_MB)
            .processes(64)
            .seal();
    };

    // the attacker binary, as seen from inside
    static char inner[4096];
    {
        const char* base = std::strrchr(self, '/');
        std::snprintf(inner, sizeof inner, "/app%s", base ? base : "/escape_corpus_test");
    }

    std::size_t n = 0;
    const auto* t = attacks::table(n);

    std::fprintf(stderr, "\nescape corpus: %zu attacks\n\n", n);

    int escaped = 0;
    int blocked = 0;
    int skipped = 0;
    int nostart = 0;

    for (std::size_t i = 0; i < n; ++i) {
        Outcome o = run_attack(make(), inner, t[i].name, t[i].needs_leaked_fd);

        const char* verdict;
        if (!o.started) {
            verdict = "DID NOT START";
            ++nostart;
        } else if (o.signalled) {
            // killed by our own seccomp filter: the strongest possible block
            verdict = "blocked (killed)";
            ++blocked;
        } else if (o.code == attacks::kEscaped) {
            verdict = "*** ESCAPED ***";
            ++escaped;
        } else if (o.code == attacks::kNotApplicable) {
            verdict = "n/a";
            ++skipped;
        } else if (o.code == kExitPlanFailed || o.code == kExitExecFailed) {
            verdict = "DID NOT START";
            ++nostart;
        } else {
            verdict = "blocked";
            ++blocked;
        }

        std::fprintf(stderr, "  %-24s %s\n", t[i].name, verdict);

        // an escape is a test failure; so is a sandbox that could not start,
        // because then the result tells us nothing.
        CHECK(o.started);
        CHECK(o.code != attacks::kEscaped);
    }

    std::fprintf(stderr, "\n  %d blocked, %d escaped, %d n/a, %d failed to start\n\n", blocked,
                 escaped, skipped, nostart);

    // ---- scoping, which is the case a namespace cannot express ------------
    //
    // net.abstract_unix passes above, but that proves less than it looks: the
    // build policy has no network, so the guest is in an empty netns and the
    // abstract socket namespace is empty for that reason alone. a netns is
    // all-or-nothing, so it stops being available the moment the guest needs
    // real network -- which is exactly when a sandbox is most interesting.
    //
    // landlock scoping (abi 6+) is what covers that gap: it closes abstract
    // sockets and cross-boundary signals INDEPENDENTLY of the network namespace.
    // so the real test is the same attack under a policy that grants network.
    //
    // it needs a REAL listener, because scoping is checked against the peer: the
    // kernel compares the listening socket's landlock domain with the caller's
    // and refuses if they differ. an unbound name has no peer to compare, so it
    // fails identically with and without scoping and proves nothing. so bind one
    // here, outside the sandbox, and hand the guest its name.
    if (host.landlock_abi >= 6) {
        static constexpr char kProbeName[] = "claybin-scope-probe";

        int lfd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(lfd >= 0);

        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        addr.sun_path[0] = '\0';
        std::memcpy(addr.sun_path + 1, kProbeName, sizeof kProbeName - 1);
        socklen_t alen = static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path) + 1 +
                                               sizeof kProbeName - 1);

        bool listening = ::bind(lfd, reinterpret_cast<struct sockaddr*>(&addr), alen) == 0 &&
                         ::listen(lfd, 4) == 0;

        std::fprintf(stderr, "  scoping, network allowed (landlock abi %u):\n",
                     host.landlock_abi);

        if (!listening) {
            // another copy of the test is already running, most likely. without a
            // listener there is nothing to prove, so say so rather than pass.
            std::fprintf(stderr, "    could not bind the probe listener, skipped\n\n");
            ::close(lfd);
        } else {
            // the control: unsandboxed, this connect must succeed. an attack that
            // cannot succeed outside the sandbox proves nothing inside it.
            {
                int s = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                int r = ::connect(s, reinterpret_cast<struct sockaddr*>(&addr), alen);
                ::close(s);
                std::fprintf(stderr, "    control (no sandbox)   %s\n",
                             r == 0 ? "reachable, as expected" : "UNREACHABLE -- test is broken");
                CHECK_EQ(r, 0);
            }

            auto with_net = [&] {
                return Policy<Draft>{}
                    .ro_bind("/usr", "/usr")
                    .bind_try("/lib", "/lib")
                    .bind_try("/lib64", "/lib64")
                    .bind_try("/bin", "/bin")
                    .ro_bind(dir, "/app")
                    .tmpfs("/tmp", 64_MB)
                    .proc_fs("/proc")
                    .dev_fs("/dev")
                    .workdir("/")
                    .connect("example.invalid", 443)
                    .env("CLAY_ABSTRACT_PROBE", kProbeName)
                    .syscall_profile(profiles::compiler_with_network())
                    .memory(256_MB)
                    .processes(64)
                    .seal();
            };

            Outcome o = run_attack(with_net(), inner, "net.abstract_unix_live", false,
                                   "CLAY_ABSTRACT_PROBE=" "claybin-scope-probe");
            std::fprintf(stderr, "    net.abstract_unix_live %s\n",
                         !o.started                     ? "DID NOT START"
                         : o.code == attacks::kEscaped   ? "*** ESCAPED ***"
                         : o.code == attacks::kNotApplicable ? "n/a (no probe name)"
                                                         : "blocked");
            CHECK(o.started);
            CHECK(o.code == attacks::kBlocked);
            ::close(lfd);
            std::fprintf(stderr, "\n");
        }
    } else {
        std::fprintf(stderr, "  scoping: skipped, landlock abi %u < 6\n\n", host.landlock_abi);
    }

#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "skip escape_corpus_test: linux only\n");
#endif
    return finish("escape_corpus_test");
}
