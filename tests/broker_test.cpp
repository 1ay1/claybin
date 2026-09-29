// seccomp user-notification brokering, end to end.
//
// this is the test that decides whether claybin is a capability system or just a
// filter. a filter says "socket() yes or no". a broker says "you may have a
// socket, and I decided that at runtime after looking at the arguments" -- and
// that is the difference between a policy and a capability.
//
// what is asserted here:
//   1. a brokered syscall really does reach the supervisor
//   2. the supervisor's deny is what the guest observes
//   3. the supervisor's allow is what the guest observes
//   4. the decision can depend on the ARGUMENTS, not just the syscall
//   5. an expired notification is refused rather than answered blind

#include "harness.hpp"

#include <cstring>

#if defined(__linux__)
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/broker/notify.hpp"
#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/shapes.hpp"

using namespace clay;
using namespace clay::test;
using namespace clay::literals;

#if defined(__linux__)
namespace {

// the guest side: try to make a socket and report what happened.
int guest_socket(int domain) {
    int s = ::socket(domain, SOCK_STREAM, 0);
    if (s < 0) return 1;  // denied
    ::close(s);
    return 0;  // allowed
}

}  // namespace
#endif

int main(int argc, char** argv) {
#if defined(__linux__)
    // guest mode
    if (argc >= 3 && std::strcmp(argv[1], "guest") == 0) {
        if (std::strcmp(argv[2], "inet") == 0) return guest_socket(AF_INET);
        if (std::strcmp(argv[2], "unix") == 0) return guest_socket(AF_UNIX);
        if (std::strcmp(argv[2], "packet") == 0) return guest_socket(17 /* AF_PACKET */);
        return 3;
    }

    auto host = probe_host();
    if (!host.seccomp_user_notif) {
        std::fprintf(stderr, "skip broker_test: kernel has no SECCOMP_RET_USER_NOTIF\n");
        return 0;
    }

    if (host.landlock_abi == 0 || !host.user_namespaces) {
        std::fprintf(stderr, "skip broker_test: host lacks landlock/userns\n");
        return 0;
    }

    static char self[4096];
    ssize_t sl = ::readlink("/proc/self/exe", self, sizeof self - 1);
    if (sl <= 0) return 1;
    self[sl] = '\0';
    static char dir[4096];
    std::snprintf(dir, sizeof dir, "%s", self);
    if (char* s = std::strrchr(dir, '/')) *s = '\0';
    static char inner[4096];
    {
        const char* base = std::strrchr(self, '/');
        std::snprintf(inner, sizeof inner, "/app%s", base ? base : "/broker_test");
    }

    // a policy that BROKERS socket() rather than allowing or denying it. this is
    // the whole point: the verdict is a runtime decision, not a compile-time one.
    auto make = [&] {
        SyscallPolicy sys = profiles::compiler();
        sys.notify(41);  // socket -> ask the supervisor
        return Policy<Draft>{}
            .ro_bind("/usr", "/usr")
            .bind_try("/lib", "/lib")
            .bind_try("/lib64", "/lib64")
            .ro_bind(dir, "/app")
            .tmpfs("/tmp", 16_MB)
            .workdir("/")
            .syscall_profile(sys)
            .seal();
    };

    // run the guest with a given handler and report its exit code.
    auto run = [&](const char* what, const broker::Handler& h) -> int {
        auto c = compile(make(), host);
        if (!c) {
            std::fprintf(stderr, "  compile failed: %s\n", to_string(c.error().code).data());
            return -1;
        }
        CHECK(c->brokers_syscalls);

        const char* argvv[] = {inner, "guest", what, nullptr};
        Command cmd{inner, argvv, nullptr};
        auto sp = spawn_in(c->plan, cmd, c->cgroup);
        if (!sp) {
            std::fprintf(stderr, "  spawn failed: %.*s errno=%d\n",
                         static_cast<int>(sp.error().mechanism.size()),
                         sp.error().mechanism.data(), sp.error().sys_errno);
            return -1;
        }
        if (sp->notify_fd < 0) {
            std::fprintf(stderr, "  no listener fd came back\n");
            return -1;
        }

        broker::Listener listener{OwnedFd{sp->notify_fd}};
        CHECK(listener.valid());

        // service notifications until the guest exits. a real supervisor would
        // poll this alongside the pidfd; here we just interleave.
        // poll the listener alongside the child. a bare blocking recv deadlocks
        // once the guest exits without another brokered call; a bare waitpid
        // never runs the handler. a real supervisor uses its event loop.
        int status = 0;
        for (;;) {
            if (::waitpid(sp->pid, &status, WNOHANG) == sp->pid) break;
            struct pollfd pfd{};
            pfd.fd = listener.fd().get();
            pfd.events = POLLIN;
            int pr = ::poll(&pfd, 1, 50);
            if (pr > 0 && (pfd.revents & POLLIN)) {
                if (!listener.poll_once(h)) break;
            } else if (pr < 0) {
                break;
            }
        }
        if (::waitpid(sp->pid, &status, WNOHANG) == 0) ::waitpid(sp->pid, &status, 0);
        if (sp->pidfd >= 0) ::close(sp->pidfd);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -2;
    };

    // -- 1 & 2: the supervisor DENIES, and the guest sees it ---------------
    {
        int seen = 0;
        auto deny_all = [&](const broker::Request& r) {
            ++seen;
            CHECK(r.nr == 41);  // it really is socket()
            return broker::Decision::deny_it(13 /* EACCES */);
        };
        int code = run("inet", deny_all);
        // the guest's socket() failed, so it returns 1
        CHECK(code == 1);
        // and the supervisor was actually consulted -- if this is 0 the syscall
        // never reached us and the test proves nothing.
        CHECK(seen > 0);
        std::fprintf(stderr, "  deny:  guest exit=%d, supervisor consulted %d time(s)\n", code,
                     seen);
    }

    // -- 3: the supervisor ALLOWS, and the guest sees THAT -----------------
    {
        int seen = 0;
        auto allow_all = [&](const broker::Request& r) {
            ++seen;
            (void)r;
            return broker::Decision::allow_it();
        };
        int code = run("inet", allow_all);
        CHECK(code == 0);  // the socket was created
        CHECK(seen > 0);
        std::fprintf(stderr, "  allow: guest exit=%d, supervisor consulted %d time(s)\n", code,
                     seen);
    }

    // -- 4: THE POINT. the decision depends on the ARGUMENTS ---------------
    // same policy, same syscall, different verdict -- decided at runtime from
    // the register values. no static filter can express this.
    {
        auto by_family = [](const broker::Request& r) {
            return broker::decide_socket(r, /*any_network_allowed=*/true);
        };
        int inet = run("inet", by_family);
        int packet = run("packet", by_family);
        CHECK(inet == 0);    // AF_INET allowed
        CHECK(packet == 1);  // AF_PACKET refused -- a packet-forging primitive
        std::fprintf(stderr, "  by-argument: AF_INET=%d AF_PACKET=%d (same policy)\n", inet,
                     packet);
    }

    // -- 5: an expired notification must be REFUSED ------------------------
    // answering a dead notification would approve a syscall nobody inspected,
    // because the kernel reuses ids. the listener has to notice.
    {
        auto c = compile(make(), host);
        CHECK(c.has_value());
        if (c) {
            const char* argvv[] = {inner, "guest", "inet", nullptr};
            Command cmd{inner, argvv, nullptr};
            auto sp = spawn_in(c->plan, cmd, c->cgroup);
            if (sp && sp->notify_fd >= 0) {
                broker::Listener listener{OwnedFd{sp->notify_fd}};
                auto req = listener.next();
                CHECK(req.has_value());
                if (req) {
                    // a live notification is valid
                    CHECK(listener.still_valid(*req));
                    // a fabricated id is not
                    broker::Request fake = *req;
                    fake.id = ~fake.id;
                    CHECK(!listener.still_valid(fake));
                    // and responding to it is refused rather than attempted
                    auto st = listener.respond(fake, broker::Decision::allow_it());
                    CHECK(!st.has_value());
                    // let the real one through so the guest can exit
                    (void)listener.respond(*req, broker::Decision::deny_it());
                }
                int status = 0;
                ::waitpid(sp->pid, &status, 0);
                if (sp->pidfd >= 0) ::close(sp->pidfd);
            }
        }
    }


#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "skip broker_test: linux only\n");
#endif
    return finish("broker_test");
}
