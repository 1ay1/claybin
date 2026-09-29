// mounts are the bubblewrap model: build a new tree rather than restrict the
// existing one. this test runs the same shape of invocation flatpak uses, and
// checks the host filesystem is genuinely ABSENT rather than merely denied.

#include "harness.hpp"

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

int probe(const char* what) {
    if (std::strcmp(what, "see_home") == 0) {
        // /home must not even EXIST in the new tree
        return ::access("/home", F_OK) == 0 ? 0 : 1;
    }
    if (std::strcmp(what, "see_etc_shadow") == 0) {
        return ::access("/etc/shadow", F_OK) == 0 ? 0 : 1;
    }
    if (std::strcmp(what, "usr_readable") == 0) {
        return ::access("/usr/bin", F_OK) == 0 ? 0 : 1;
    }
    if (std::strcmp(what, "usr_readonly") == 0) {
        // a read-only bind must reject writes
        int fd = ::open("/usr/.clay_probe", O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) {
            ::close(fd);
            return 0;  // escape: we wrote to a ro bind
        }
        return 1;
    }
    if (std::strcmp(what, "tmp_writable") == 0) {
        int fd = ::open("/tmp/clay_probe", O_WRONLY | O_CREAT, 0600);
        if (fd < 0) return 1;
        ::close(fd);
        return 0;  // expected: tmpfs is writable
    }
    if (std::strcmp(what, "dev_null") == 0) {
        int fd = ::open("/dev/null", O_WRONLY);
        if (fd < 0) return 1;
        ::close(fd);
        return 0;
    }
    if (std::strcmp(what, "dev_null_create") == 0) {
        // O_CREAT on the EXISTING /dev/null, which is what a shell does for
        // `cmd > /dev/null` -- it always passes O_CREAT|O_TRUNC.
        //
        // this is a separate probe from dev_null on purpose: plain O_WRONLY
        // succeeded for months while the redirect was broken, so the cheaper
        // check proved nothing. the cause was the /dev tmpfs being mounted with
        // the default mode 1777, whose STICKY bit makes the kernel refuse
        // O_CREAT on a file the guest does not own -- and every device node
        // there is bind-mounted from the host, owned by the outer root.
        int fd = ::open("/dev/null", O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) return 1;
        ::close(fd);
        return 0;
    }
    if (std::strcmp(what, "tmpfs_size") == 0) {
        // the tmpfs size must be a real limit. it used to be accepted and
        // dropped, so a guest got an unbounded tmpfs and filling /tmp was host
        // memory pressure rather than a contained ENOSPC.
        //
        // the policy asks for 64 MB, so writing 96 MB must fail with ENOSPC. any
        // other outcome -- success, or a different errno -- is a fail.
        int fd = ::open("/tmp/fill", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) return 2;
        static char buf[256 * 1024];
        std::memset(buf, 'x', sizeof buf);
        for (int i = 0; i < 384; ++i) {  // 96 MB
            ssize_t w = ::write(fd, buf, sizeof buf);
            if (w < 0) {
                int e = errno;
                ::close(fd);
                return e == ENOSPC ? 0 : 3;
            }
        }
        ::close(fd);
        return 1;  // wrote 96 MB into a 64 MB tmpfs: the size is not a limit
    }
    if (std::strcmp(what, "dev_mem") == 0) {
        // /dev/mem must be absent from the allow-listed /dev
        return ::access("/dev/mem", F_OK) == 0 ? 0 : 1;
    }
    if (std::strcmp(what, "proc_host_pids") == 0) {
        // in a pid namespace with a fresh procfs, pid 2 of the host is invisible
        return ::access("/proc/1/cmdline", F_OK) == 0 ? 0 : 1;
    }
    return 3;
}

struct Res {
    bool started{false};
    int code{-1};
    Error err{};
};

Res run(const Policy<Sealed>& pol, const char* what, const char* self) {
    Res r;
    auto c = compile(pol, probe_host());
    if (!c) {
        r.err = c.error();
        return r;
    }
    const char* argv[] = {self, "probe", what, nullptr};
    Command cmd{self, argv, nullptr};
    auto sp = spawn(c->plan, cmd);
    if (!sp) {
        r.err = sp.error();
        return r;
    }
    r.started = true;
    int st = 0;
    ::waitpid(sp->pid, &st, 0);
    if (sp->pidfd >= 0) ::close(sp->pidfd);
    r.code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return r;
}

}  // namespace
#endif

int main(int argc, char** argv) {
#if defined(__linux__)
    if (argc >= 3 && std::strcmp(argv[1], "probe") == 0) return probe(argv[2]);

    static char self[4096];
    ssize_t n = ::readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) return 1;
    self[n] = '\0';
    static char dir[4096];
    std::snprintf(dir, sizeof dir, "%s", self);
    if (char* s = std::strrchr(dir, '/')) *s = '\0';

    auto host = probe_host();
    if (!host.mount_namespaces || !host.user_namespaces) {
        std::fprintf(stderr, "skip mount_test: no mount/user namespaces\n");
        return 0;
    }

    // the flatpak-shaped invocation, as claybin spells it. compare:
    //   bwrap --unshare-all --ro-bind /usr /usr --symlink usr/lib /lib \
    //         --proc /proc --dev /dev --tmpfs /tmp --chdir / -- CMD
    //
    // note the test binary is bound at /app, NOT at its host path: binding it
    // at /home/.../build would recreate /home inside the sandbox and make the
    // "is the host tree absent" checks vacuously false. remapping is the point
    // of the mount model, so the test uses it.
    auto make = [&] {
        return Policy<Draft>{}
            .ro_bind("/usr", "/usr")
            .ro_bind(dir, "/app")   // the test binary, remapped
            .symlink("usr/lib", "/lib")
            .symlink("usr/lib", "/lib64")
            .symlink("usr/bin", "/bin")
            .proc_fs("/proc")
            .dev_fs("/dev")
            .tmpfs("/tmp", 64_MB)
            .workdir("/")
            .syscall_profile(profiles::compiler())
            .seal();
    };

    // the path the binary has INSIDE the sandbox
    static char inner[4096];
    {
        const char* base = std::strrchr(self, '/');
        std::snprintf(inner, sizeof inner, "/app%s", base ? base : "/mount_test");
    }

    auto expect = [&](const char* what, int want, const char* why) {
        auto r = run(make(), what, inner);
        if (!r.started) {
            std::fprintf(stderr, "  [%s] did not start: %s / %.*s errno=%d\n", what,
                         to_string(r.err.code).data(),
                         static_cast<int>(r.err.mechanism.size()), r.err.mechanism.data(),
                         r.err.sys_errno);
        }
        CHECK(r.started);
        if (r.started && r.code != want)
            std::fprintf(stderr, "  [%s] got %d want %d (%s)\n", what, r.code, want, why);
        CHECK(r.code == want);
    };

    // the granted tree works
    expect("usr_readable", 0, "/usr was bound in");
    expect("tmp_writable", 0, "tmpfs is writable");
    expect("dev_null", 0, "/dev/null was bound in");
    // and a shell redirect over it works, which is a stricter question: it needs
    // O_CREAT to succeed on a bind-mounted node, so the /dev tmpfs must not be
    // mounted sticky.
    expect("dev_null_create", 0, "`cmd > /dev/null` must work");
    // the tmpfs size is a real limit, not a decoration
    expect("tmpfs_size", 0, "a 64 MB tmpfs must ENOSPC before 96 MB");

    // and the host tree is ABSENT, not merely denied. this is the property
    // landlock alone cannot give you: there is no path to the host's /home.
    expect("see_home", 1, "/home must not exist in the new root");
    expect("see_etc_shadow", 1, "/etc must not exist in the new root");
    expect("dev_mem", 1, "/dev is an allow-list, not a devtmpfs");

    // a read-only bind must actually be read-only. the kernel ignores MS_RDONLY
    // on the initial bind, so this catches a missing remount.
    expect("usr_readonly", 1, "ro-bind must reject writes");

#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "skip mount_test: linux only\n");
#endif
    return finish("mount_test");
}
