// mounts are the bubblewrap model: build a new tree rather than restrict the
// existing one. this test runs the same shape of invocation flatpak uses, and
// checks the host filesystem is genuinely ABSENT rather than merely denied.

#include "harness.hpp"

#include <cstring>

#if defined(__linux__)
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
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

    // ---- the symlink escape --------------------------------------------
    //
    // this one is not about what the GUEST can do -- it is about what claybin
    // itself does while building the tree, before the guest exists.
    //
    // --file and --bind-data materialise a caller's fd at a guest path. that
    // path is under our staging root, but the directories along the way can come
    // from a bind the caller also asked for, and a symlink planted in one of
    // those redirects the write. measured before the fix: a bind of a directory
    // containing `out -> /tmp/victim` plus `--file 9 /work/out/canary` wrote the
    // bytes to /tmp/victim/canary, on the HOST, outside the sandbox. bubblewrap
    // refuses the same invocation.
    //
    // so the assertion is that setup FAILS. a test that spawns and inspects the
    // guest cannot see this: by the time the guest runs, the damage is done and
    // the guest's own view looks perfectly normal.
    {
        char dir[] = "/tmp/clay-symlink-XXXXXX";
        if (::mkdtemp(dir) != nullptr) {
            char evil[256], victim[256], canary[256], payload[256];
            std::snprintf(evil, sizeof evil, "%s/evil", dir);
            std::snprintf(victim, sizeof victim, "%s/victim", dir);
            std::snprintf(canary, sizeof canary, "%s/victim/canary", dir);
            std::snprintf(payload, sizeof payload, "%s/payload", dir);
            ::mkdir(evil, 0755);
            ::mkdir(victim, 0755);

            // the canary the escape would overwrite, and the bytes it would use
            static constexpr char kCanary[] = "UNTOUCHED";
            int fd = ::open(canary, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            CHECK(fd >= 0);
            if (fd >= 0) {
                ssize_t wr = ::write(fd, kCanary, sizeof kCanary - 1);
                (void)wr;
                ::close(fd);
            }
            fd = ::open(payload, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                ssize_t wr = ::write(fd, "PWNED", 5);
                (void)wr;
                ::close(fd);
            }

            // the trap: a symlink inside the directory that gets bound in,
            // pointing back out at the victim.
            char link[256];
            std::snprintf(link, sizeof link, "%s/out", evil);
            CHECK_EQ(::symlink(victim, link), 0);

            int content = ::open(payload, O_RDONLY | O_CLOEXEC);
            CHECK(content >= 0);
            if (content >= 0) {
                auto pol = Policy<Draft>{}
                               .ro_bind("/usr", "/usr")
                               .bind_try("/lib", "/lib")
                               .bind_try("/lib64", "/lib64")
                               .bind_try("/bin", "/bin")
                               .bind(evil, "/work")
                               .proc_fs("/proc")
                               .dev_fs("/dev")
                               .file_from_fd(BorrowedFd{content}, "/work/out/canary")
                               .workdir("/")
                               .syscall_profile(profiles::compiler())
                               .seal();

                auto c = compile(pol, probe_host());
                CHECK(c.has_value());
                if (c) {
                    const char* av[] = {"/bin/true", nullptr};
                    Command cmd{"/bin/true", av, nullptr};
                    auto s = spawn(c->plan, cmd);
                    if (s) {
                        int st = 0;
                        ::waitpid(s->pid, &st, 0);
                        if (s->pidfd >= 0) ::close(s->pidfd);
                        // setup must NOT have succeeded quietly. the child exits
                        // with kExitPlanFailed when an op refuses.
                        int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
                        if (code != kExitPlanFailed)
                            std::fprintf(stderr,
                                         "  symlink escape: setup did not refuse (exit %d)\n",
                                         code);
                        CHECK_EQ(code, kExitPlanFailed);
                    }
                }
                ::close(content);
            }

            // whatever happened, the host file must be untouched. this is the
            // check that actually matters -- the exit code is a proxy for it.
            char buf[64] = {};
            fd = ::open(canary, O_RDONLY);
            if (fd >= 0) {
                ssize_t n = ::read(fd, buf, sizeof buf - 1);
                if (n < 0) n = 0;
                buf[n] = '\0';
                ::close(fd);
            }
            if (std::strcmp(buf, kCanary) != 0)
                std::fprintf(stderr, "  *** ESCAPED: host file now reads '%s'\n", buf);
            CHECK_EQ(std::strcmp(buf, kCanary), 0);

            // ---- the same hole, two more ways in --------------------------
            //
            // fixing --file alone was not enough, which is the real lesson here.
            // every op that writes into the guest tree resolves a path, and each
            // one that did so unconfined was its own escape. both of these were
            // verified to plant things on the host before the fix:
            //
            //   --symlink x /work/out/planted  -> symlink at /tmp/victim/planted
            //   --bind src /work/out/mnt       -> directory at /tmp/victim/mnt
            //
            // bubblewrap refuses both. so the check is per-OP, not per-symptom:
            // a future op that forgets to confine is a new escape, and only a
            // test shaped like this will say so.
            struct Case {
                const char* name;
                bool symlink;  // else: a bind destination
            };
            static constexpr Case kCases[] = {
                {"--symlink", true},
                {"--bind destination", false},
            };

            for (const auto& cs : kCases) {
                // a fresh marker each time, so one case cannot mask another
                char probe[256];
                std::snprintf(probe, sizeof probe, "%s/victim/planted", dir);
                ::unlink(probe);
                ::rmdir(probe);

                auto draft = Policy<Draft>{}
                                 .ro_bind("/usr", "/usr")
                                 .bind_try("/lib", "/lib")
                                 .bind_try("/lib64", "/lib64")
                                 .bind_try("/bin", "/bin")
                                 .bind(evil, "/work")
                                 .proc_fs("/proc")
                                 .dev_fs("/dev")
                                 .workdir("/");
                auto pol = cs.symlink
                               ? std::move(draft).symlink("/etc/passwd", "/work/out/planted")
                                     .syscall_profile(profiles::compiler())
                                     .seal()
                               : std::move(draft).bind(victim, "/work/out/planted")
                                     .syscall_profile(profiles::compiler())
                                     .seal();

                auto cc = compile(pol, probe_host());
                CHECK(cc.has_value());
                if (!cc) continue;
                const char* av2[] = {"/bin/true", nullptr};
                Command cmd2{"/bin/true", av2, nullptr};
                auto s2 = spawn(cc->plan, cmd2);
                if (s2) {
                    int st2 = 0;
                    ::waitpid(s2->pid, &st2, 0);
                    if (s2->pidfd >= 0) ::close(s2->pidfd);
                    int code2 = WIFEXITED(st2) ? WEXITSTATUS(st2) : -1;
                    if (code2 != kExitPlanFailed)
                        std::fprintf(stderr, "  %s escape: setup did not refuse (exit %d)\n",
                                     cs.name, code2);
                    CHECK_EQ(code2, kExitPlanFailed);
                }

                // and nothing appeared on the host through the symlink
                struct stat sb {};
                bool appeared = ::lstat(probe, &sb) == 0;
                if (appeared)
                    std::fprintf(stderr, "  *** ESCAPED via %s: %s exists on the host\n",
                                 cs.name, probe);
                CHECK(!appeared);
            }

            // tidy up
            ::unlink(link);
            ::unlink(canary);
            ::unlink(payload);
            ::rmdir(evil);
            ::rmdir(victim);
            ::rmdir(dir);
        }
    }

    // ---- why bind_fd resolves to a path, pinned ------------------------
    //
    // mounts.hpp explains that binding a descriptor would be better than
    // binding the path we resolve it to, and that the kernel will not let us.
    // the comment used to give the WRONG reason -- it said mounting a magic
    // symlink is refused outright, and it is not. this pins the real rule so
    // nobody spends an afternoon rediscovering it, and so it is noticed if a
    // future kernel changes it (at which point bind_fd can be made race-free).
    //
    // the rule: mount("/proc/self/fd/N", MS_BIND) works, but ONLY for a
    // descriptor opened in the same mount namespace as the mount call.
    {
        char dir[] = "/tmp/clay-fdmount-XXXXXX";
        if (::mkdtemp(dir) != nullptr) {
            char src[256], dst[256];
            std::snprintf(src, sizeof src, "%s/src", dir);
            std::snprintf(dst, sizeof dst, "%s/dst", dir);
            ::mkdir(src, 0755);
            ::mkdir(dst, 0755);

            // opened in OUR namespace, before the child unshares
            int outer = ::open(src, O_PATH | O_DIRECTORY | O_CLOEXEC);
            CHECK(outer >= 0);

            if (outer >= 0) {
                // read the uid BEFORE unsharing. after it, getuid() returns the
                // overflow uid (65534) and the map line names a uid we do not
                // own, so the write fails with EPERM -- which reads as "no
                // unprivileged userns here" and silently skips the test.
                uid_t real_uid = ::getuid();
                gid_t real_gid = ::getgid();
                pid_t p = ::fork();
                if (p == 0) {
                    // a fresh mount namespace, exactly as the sandbox makes
                    if (::unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) ::_exit(70);
                    // deny setgroups then map ourselves, or nothing is permitted
                    int f = ::open("/proc/self/setgroups", O_WRONLY);
                    if (f >= 0) {
                        ssize_t w = ::write(f, "deny", 4);
                        (void)w;
                        ::close(f);
                    }
                    char b[64];
                    f = ::open("/proc/self/uid_map", O_WRONLY);
                    int n = std::snprintf(b, sizeof b, "0 %u 1\n", real_uid);
                    if (f < 0 || ::write(f, b, static_cast<std::size_t>(n)) != n) ::_exit(71);
                    ::close(f);
                    f = ::open("/proc/self/gid_map", O_WRONLY);
                    n = std::snprintf(b, sizeof b, "0 %u 1\n", real_gid);
                    if (f < 0 || ::write(f, b, static_cast<std::size_t>(n)) != n) ::_exit(73);
                    ::close(f);
                    ::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);

                    char magic[64];
                    std::snprintf(magic, sizeof magic, "/proc/self/fd/%d", outer);
                    int outer_rc = ::mount(magic, dst, nullptr, MS_BIND, nullptr);
                    int outer_err = errno;
                    if (outer_rc == 0) ::umount2(dst, MNT_DETACH);

                    // and the same thing for an fd opened AFTER the unshare
                    int inner = ::open(src, O_PATH | O_DIRECTORY | O_CLOEXEC);
                    if (inner < 0) ::_exit(72);
                    std::snprintf(magic, sizeof magic, "/proc/self/fd/%d", inner);
                    int inner_rc = ::mount(magic, dst, nullptr, MS_BIND, nullptr);
                    if (inner_rc == 0) ::umount2(dst, MNT_DETACH);

                    // expected: the outer fd is refused with EINVAL, the inner
                    // one works. exit code encodes both so the parent can tell
                    // which half changed.
                    int code = 0;
                    if (!(outer_rc < 0 && outer_err == EINVAL)) code |= 1;
                    if (inner_rc != 0) code |= 2;
                    ::_exit(code);
                }
                int st = 0;
                ::waitpid(p, &st, 0);
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
                if (code >= 70) {
                    // no unprivileged userns on this box: nothing to assert
                    std::fprintf(stderr, "  skip fd-mount rule (setup %d)\n", code);
                } else {
                    if (code & 1)
                        std::fprintf(stderr,
                                     "  fd-mount rule CHANGED: a cross-namespace fd is now\n"
                                     "  mountable -- bind_fd can be made race-free\n");
                    if (code & 2)
                        std::fprintf(stderr,
                                     "  fd-mount rule CHANGED: a same-namespace fd is no\n"
                                     "  longer mountable\n");
                    CHECK_EQ(code, 0);
                }
                ::close(outer);
            }
            ::rmdir(src);
            ::rmdir(dst);
            ::rmdir(dir);
        }
    }

#else
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "skip mount_test: linux only\n");
#endif
    return finish("mount_test");
}
