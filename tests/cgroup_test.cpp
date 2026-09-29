// cgroup limits are the easiest thing in a sandbox to claim and not deliver: the
// write succeeds, the report says `strong`, and nobody notices until a guest
// eats all the memory. so this test does not check that we wrote the file -- it
// checks that a guest which TRIES to exceed the limit actually gets stopped.

#include "harness.hpp"

#include <cstring>

#if defined(__linux__)
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/linux/cgroup.hpp"
#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/shapes.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

#if defined(__linux__)
namespace {

// the guest side: try to consume more than we were allowed.
int hog_memory(std::size_t target_mb) {
    // touch every page, so this is resident memory and not just address space.
    // RLIMIT_AS would stop the mmap; only a cgroup stops the touching.
    const std::size_t chunk = 8u << 20;
    std::size_t total = 0;
    while (total < target_mb << 20) {
        auto* p = static_cast<volatile char*>(std::malloc(chunk));
        if (!p) return 1;  // allocation refused: the limit held
        for (std::size_t i = 0; i < chunk; i += 4096) p[i] = 1;
        total += chunk;
    }
    return 0;  // we got all of it: the limit did NOT hold
}

int fork_bomb(int target) {
    int made = 0;
    for (int i = 0; i < target; ++i) {
        pid_t p = ::fork();
        if (p < 0) return 1;  // refused: the limit held
        if (p == 0) {
            ::pause();
            ::_exit(0);
        }
        ++made;
    }
    // clean up before reporting success
    for (int i = 0; i < made; ++i) ::kill(-1, SIGKILL);
    return 0;  // we made them all: the limit did NOT hold
}

}  // namespace
#endif

int main(int argc, char** argv) {
#if defined(__linux__)
    if (argc >= 3 && std::strcmp(argv[1], "hog") == 0)
        return hog_memory(static_cast<std::size_t>(std::atoi(argv[2])));
    if (argc >= 3 && std::strcmp(argv[1], "bomb") == 0)
        return fork_bomb(std::atoi(argv[2]));

    auto probe = cgroup::probe();
    std::fprintf(stderr, "cgroup: %s\n", cgroup::to_string(probe.availability));
    if (probe.availability != cgroup::Availability::delegated) {
        std::fprintf(stderr, "skip cgroup_test: %s\n", probe.reason);
        return 0;
    }

    static char self[4096];
    ssize_t n = ::readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) return 1;
    self[n] = '\0';
    static char dir[4096];
    std::snprintf(dir, sizeof dir, "%s", self);
    if (char* s = std::strrchr(dir, '/')) *s = '\0';

    auto host = probe_host();

    // -- the report must only claim strong when we really got a cgroup -----
    {
        auto pol = shapes::system_ro()
                       .bind_try(dir, dir)
                       .memory(64_MB)
                       .processes(16)
                       .syscall_profile(profiles::compiler())
                       .seal();
        auto c = compile(pol, host);
        CHECK(c.has_value());
        if (c) {
            CHECK(c->cgroup.valid());
            CHECK(c->guarantees.strength(CapId::mem_limit) == Enforcement::strong);
            CHECK(c->guarantees.strength(CapId::pid_limit) == Enforcement::strong);
            // and the claim is backed by a real cgroup directory
            CHECK(!c->cgroup.path().empty());
        }
    }

    // -- a memory hog must be STOPPED, not merely reported -----------------
    {
        auto pol = shapes::system_ro()
                       .bind_try(dir, dir)
                       .memory(64_MB)
                       .syscall_profile(profiles::compiler())
                       .seal();
        auto c = compile(pol, host);
        CHECK(c.has_value());
        if (c && c->cgroup.valid()) {
            const char* argvv[] = {self, "hog", "512", nullptr};
            Command cmd{self, argvv, nullptr};
            auto sp = spawn_in(c->plan, cmd, c->cgroup);
            if (!sp)
                std::fprintf(stderr, "  hog did not start: %.*s errno=%d\n",
                             static_cast<int>(sp.error().mechanism.size()),
                             sp.error().mechanism.data(), sp.error().sys_errno);
            CHECK(sp.has_value());
            if (sp) {
                int st = 0;
                ::waitpid(sp->pid, &st, 0);
                if (sp->pidfd >= 0) ::close(sp->pidfd);
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
                // asked for 512 MB with a 64 MB cap. either malloc failed (1)
                // or the kernel OOM-killed it. code 0 would mean it got all
                // 512 MB, i.e. the limit was decorative.
                bool stopped = WIFSIGNALED(st) || code == 1 || code == 137 ||
                               (code > 128 && code < 160);
                if (!stopped)
                    std::fprintf(stderr, "  MEMORY LIMIT NOT ENFORCED: exit=%d\n", code);
                CHECK(stopped);
            }
        }
    }

    // -- a fork bomb must hit pids.max -------------------------------------
    {
        auto pol = shapes::system_ro()
                       .bind_try(dir, dir)
                       .processes(8)
                       .syscall_profile(profiles::compiler())
                       .seal();
        auto c = compile(pol, host);
        CHECK(c.has_value());
        if (c && c->cgroup.valid()) {
            const char* argvv[] = {self, "bomb", "200", nullptr};
            Command cmd{self, argvv, nullptr};
            auto sp = spawn_in(c->plan, cmd, c->cgroup);
            CHECK(sp.has_value());
            if (sp) {
                int st = 0;
                ::waitpid(sp->pid, &st, 0);
                if (sp->pidfd >= 0) ::close(sp->pidfd);
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
                bool stopped = WIFSIGNALED(st) || code != 0;
                if (!stopped) std::fprintf(stderr, "  PID LIMIT NOT ENFORCED\n");
                CHECK(stopped);
            }
        }
    }

    // -- the cgroup is cleaned up ------------------------------------------
    {
        std::string path;
        {
            auto pol = shapes::system_ro().memory(64_MB)
                           .syscall_profile(profiles::compiler()).seal();
            auto c = compile(pol, host);
            if (c && c->cgroup.valid()) path = c->cgroup.path();
            // c goes out of scope here; the Group destructor should rmdir
        }
        if (!path.empty()) {
            CHECK(::access(path.c_str(), F_OK) != 0);
        }
    }

#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "skip cgroup_test: linux only\n");
#endif
    return finish("cgroup_test");
}
