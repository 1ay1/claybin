// claybin-run: a bubblewrap-compatible front end.
//
// the point is drop-in replacement: the same flags mean the same things, so an
// existing --ro-bind/--proc/--dev invocation works unchanged. where claybin
// differs it is by being STRICTER, never looser:
//
//   - every bind also emits the matching landlock rule, so a path is checked by
//     two independent mechanisms rather than one
//   - a seccomp filter is installed by default; bwrap only does that if the
//     caller passes a pre-compiled BPF program via --seccomp
//   - we refuse rather than continue when a wall cannot be built (bwrap's
//     --not-a-security-boundary is the opposite default)
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(__linux__)
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;

namespace {

// case-insensitive compare, for the ALL keyword on --cap-add/--cap-drop.
bool strcasecmp_eq(const char* a, const char* b) {
    for (; *a && *b; ++a, ++b) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return *a == '\0' && *b == '\0';
}

void usage() {
    std::fprintf(stderr,
                 "usage: claybin-run [OPTIONS...] [--] COMMAND [ARGS...]\n"
                 "\n"
                 "bubblewrap-compatible options:\n"
                 "  --ro-bind SRC DST      bind SRC at DST, read-only\n"
                 "  --bind SRC DST         bind SRC at DST, read-write\n"
                 "  --dev-bind SRC DST     bind allowing device nodes\n"
                 "  --ro-bind-try SRC DST  like --ro-bind, skip if SRC is missing\n"
                 "  --bind-try SRC DST     like --bind, skip if SRC is missing\n"
                 "  --proc DST             mount a new procfs at DST\n"
                 "  --dev DST              mount a minimal /dev at DST\n"
                 "  --tmpfs DST            mount a tmpfs at DST\n"
                 "  --overlay-src SRC      add a lower layer for the next overlay\n"
                 "  --overlay UP WORK DST  writable overlay at DST\n"
                 "  --tmp-overlay DST      overlay whose writes are discarded\n"
                 "  --ro-overlay DST       read-only overlay (needs 2+ srcs)\n"
                 "  --ro-bind-fd FD DST    bind what FD refers to, read-only\n"
                 "  --bind-fd FD DST       bind what FD refers to\n"
                 "  --file FD DST          write FD's contents to a file at DST\n"
                 "  --bind-data FD DST     bind FD's contents (backing file unlinked)\n"
                 "  --ro-bind-data FD DST  same, read-only\n"
                 "  --dir DST              create a directory\n"
                 "  --symlink TGT DST      create a symlink\n"
                 "  --chdir DIR            working directory inside the sandbox\n"
                 "  --hostname NAME        set the sandbox hostname\n"
                 "  --setenv VAR VAL       set an environment variable\n"
                 "  --unshare-all          unshare every namespace (default)\n"
                 "  --share-net            keep the network namespace\n"
                 "  --size BYTES           size for the next --tmpfs\n"
                 "\n"
                 "claybin additions:\n"
                 "  --profile NAME         syscall profile: base|proc|fs|net|compiler|compiler-net\n"
                 "  --deny PATH            punch a landlock hole inside a bind\n"
                 "  --allow-port PORT      allow TCP connect to PORT only (landlock, abi4+)\n"
                 "  --allow-bind-port PORT allow TCP bind to PORT only\n"
                 "  --memory BYTES         memory cap (cgroup2 when available)\n"
                 "  --processes N          max processes (cgroup2 pids.max)\n"
                 "  --cpu-percent N        cpu cap, 100 = one core (cgroup2 cpu.max)\n"
                 "  --audit                compile THESE flags, print the plan and guarantee\n"
                 "                         report, and exit without spawning. this is the tool\n"
                 "                         for 'what will my sandbox actually do' -- claybin-audit\n"
                 "                         reports host capabilities against a fixed example.\n"
                 "  --require LEVEL        fail unless every wall reaches LEVEL\n");
}

}  // namespace

int main(int argc, char** argv) {
#if !defined(__linux__)
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "claybin-run: linux only\n");
    return 1;
#else
    if (argc < 2) {
        usage();
        return 1;
    }

    // --args reads NUL-separated arguments from an fd, and they have to be
    // parsed as if they had been on the command line. rather than splice mid-loop
    // (which would mean mutating what we are iterating), do a pre-pass: expand
    // every --args into a flat vector, then parse THAT.
    std::vector<std::string> argstore;
    std::vector<const char*> args;
    args.push_back(argv[0]);
    for (int k = 1; k < argc; ++k) {
        if (std::strcmp(argv[k], "--args") == 0 && k + 1 < argc) {
            int fd = static_cast<int>(std::strtol(argv[k + 1], nullptr, 10));
            std::string blob;
            char rb[4096];
            for (;;) {
                ssize_t n = ::read(fd, rb, sizeof rb);
                if (n <= 0) break;
                blob.append(rb, static_cast<std::size_t>(n));
            }
            ::close(fd);
            for (std::size_t p = 0; p < blob.size();) {
                std::size_t e = blob.find('\0', p);
                if (e == std::string::npos) e = blob.size();
                if (e > p) argstore.push_back(blob.substr(p, e - p));
                p = e + 1;
            }
            ++k;  // skip the fd number
            continue;
        }
        argstore.emplace_back(argv[k]);
    }
    for (const auto& s : argstore) args.push_back(s.c_str());
    const int eargc = static_cast<int>(args.size());
    const char* const* eargv = args.data();

    auto policy = Policy<Draft>{};
    bool share_net = false;
    bool audit_only = false;
    Enforcement require_level = Enforcement::none;
    std::uint64_t next_size = 0;
    const char* profile_name = "compiler";
    std::vector<std::string> denies;
    std::vector<std::string> unset_keys;
    std::vector<std::string> overlay_srcs;
    std::vector<std::string> remount_ro;
    const char* argv0_override = nullptr;
    std::uint32_t next_perms = 0;
    bool new_session = false;
    bool die_with_parent = false;
    std::vector<std::string> lock_files;
    std::vector<std::pair<std::uint32_t, std::string>> chmods;
    int info_fd = -1;
    int json_fd = -1;
    int sync_fd = -1;
    int block_fd = -1;
    int userns_block_fd = -1;
    int args_fd = -1;
    std::vector<std::string> extra_args;
    bool disable_nested_userns = false;
    bool clear_env = false;
    bool inherit_env = true;  // bwrap inherits unless --clearenv

    int i = 1;
    auto need = [&](int n, const char* what) -> bool {
        if (i + n >= argc) {
            std::fprintf(stderr, "claybin-run: %s needs %d argument(s)\n", what, n);
            return false;
        }
        return true;
    };

    for (; i < eargc; ++i) {
        const char* a = eargv[i];
        if (std::strcmp(a, "--") == 0) {
            ++i;
            break;
        }
        if (a[0] != '-') break;

        if (std::strcmp(a, "--help") == 0) {
            usage();
            return 0;
        } else if (std::strcmp(a, "--ro-bind") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).ro_bind(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--bind") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--dev-bind") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).dev_bind(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--ro-bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(eargv[i + 1], eargv[i + 2], true);
            i += 2;
        } else if (std::strcmp(a, "--bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(eargv[i + 1], eargv[i + 2], false);
            i += 2;
        } else if (std::strcmp(a, "--dev-bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(eargv[i + 1], eargv[i + 2], false);
            i += 2;
        } else if (std::strcmp(a, "--proc") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).proc_fs(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--dev") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).dev_fs(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--tmpfs") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).tmpfs(eargv[i + 1],
                                             next_size ? Bytes{next_size} : Bytes::unlimited());
            next_size = 0;
            i += 1;
        } else if (std::strcmp(a, "--size") == 0) {
            if (!need(1, a)) return 1;
            next_size = std::strtoull(eargv[i + 1], nullptr, 10);
            i += 1;
        } else if (std::strcmp(a, "--memory") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).memory(Bytes{std::strtoull(eargv[i + 1], nullptr, 10)});
            i += 1;
        } else if (std::strcmp(a, "--processes") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).processes(std::strtoull(eargv[i + 1], nullptr, 10));
            i += 1;
        } else if (std::strcmp(a, "--cpu-percent") == 0) {
            // the library has always supported this and the tool never exposed
            // it, so `resource.cpu` read `none` on every audit -- which looked
            // like a missing capability rather than a missing flag.
            if (!need(1, a)) return 1;
            policy = std::move(policy).cpu_percent(
                static_cast<std::uint32_t>(std::strtoul(eargv[i + 1], nullptr, 10)));
            i += 1;
        } else if (std::strcmp(a, "--dir") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).mkdir(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--symlink") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).symlink(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--chdir") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).workdir(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--hostname") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).hostname(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--argv0") == 0) {
            if (!need(1, a)) return 1;
            argv0_override = eargv[i + 1];
            i += 1;
        } else if (std::strcmp(a, "--new-session") == 0) {
            new_session = true;
        } else if (std::strcmp(a, "--die-with-parent") == 0) {
            die_with_parent = true;
        } else if (std::strcmp(a, "--remount-ro") == 0) {
            if (!need(1, a)) return 1;
            remount_ro.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--perms") == 0) {
            if (!need(1, a)) return 1;
            next_perms = static_cast<std::uint32_t>(std::strtoul(eargv[i + 1], nullptr, 8));
            i += 1;
        } else if (std::strcmp(a, "--version") == 0) {
            std::printf("claybin-run (claybin) 0.1.0\n");
            return 0;
        } else if (std::strcmp(a, "--level-prefix") == 0 ||
                   std::strcmp(a, "--assert-userns-disabled") == 0) {
            // accepted and ignored: these change bwrap's own diagnostics or
            // assert a host property we already report through --audit.
        } else if (std::strcmp(a, "--mqueue") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).mqueue(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--seccomp") == 0 ||
                   std::strcmp(a, "--add-seccomp-fd") == 0) {
            if (!need(1, a)) return 1;
            // claybin compiles its own filter from a profile. accepting a
            // foreign BPF program is planned, but silently ignoring the flag
            // would mean running with OUR filter while the caller believes
            // theirs is in force -- the worst possible outcome.
            std::fprintf(stderr,
                         "claybin-run: %s not supported. claybin compiles its own "
                         "seccomp filter; use --profile to choose one.\n", a);
            return 1;
        } else if (std::strcmp(a, "--bind-fd") == 0 ||
                   std::strcmp(a, "--ro-bind-fd") == 0) {
            if (!need(2, a)) return 1;
            char* end = nullptr;
            long fd = std::strtol(eargv[i + 1], &end, 10);
            if (end == eargv[i + 1] || fd < 0) {
                std::fprintf(stderr, "claybin-run: %s: invalid fd '%s'\n", a, eargv[i + 1]);
                return 1;
            }
            policy = std::move(policy).bind_fd(BorrowedFd{static_cast<int>(fd)}, eargv[i + 2],
                                               std::strcmp(a, "--ro-bind-fd") == 0);
            i += 2;
        } else if (std::strcmp(a, "--file") == 0) {
            if (!need(2, a)) return 1;
            char* end = nullptr;
            long fd = std::strtol(eargv[i + 1], &end, 10);
            if (end == eargv[i + 1] || fd < 0) {
                std::fprintf(stderr, "claybin-run: --file: invalid fd '%s'\n", eargv[i + 1]);
                return 1;
            }
            policy = std::move(policy).file_from_fd(BorrowedFd{static_cast<int>(fd)},
                                                    eargv[i + 2],
                                                    next_perms ? next_perms : 0666u);
            next_perms = 0;
            i += 2;
        } else if (std::strcmp(a, "--bind-data") == 0 ||
                   std::strcmp(a, "--ro-bind-data") == 0) {
            if (!need(2, a)) return 1;
            char* end = nullptr;
            long fd = std::strtol(eargv[i + 1], &end, 10);
            if (end == eargv[i + 1] || fd < 0) {
                std::fprintf(stderr, "claybin-run: %s: invalid fd '%s'\n", a, eargv[i + 1]);
                return 1;
            }
            policy = std::move(policy).bind_data(BorrowedFd{static_cast<int>(fd)}, eargv[i + 2],
                                                 std::strcmp(a, "--ro-bind-data") == 0,
                                                 next_perms ? next_perms : 0666u);
            next_perms = 0;
            i += 2;
        } else if (std::strcmp(a, "--uid") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).uid(
                static_cast<std::uint32_t>(std::strtoul(eargv[i + 1], nullptr, 10)));
            i += 1;
        } else if (std::strcmp(a, "--gid") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).gid(
                static_cast<std::uint32_t>(std::strtoul(eargv[i + 1], nullptr, 10)));
            i += 1;
        } else if (std::strcmp(a, "--cap-add") == 0) {
            if (!need(1, a)) return 1;
            if (strcasecmp_eq(eargv[i + 1], "ALL")) {
                std::fprintf(stderr,
                             "claybin-run: --cap-add ALL is refused. a sandbox holding every "
                             "capability is not a sandbox.\n");
                return 1;
            }
            int cap = cap_from_name(eargv[i + 1]);
            if (cap < 0) {
                std::fprintf(stderr, "claybin-run: unknown capability '%s'\n", eargv[i + 1]);
                return 1;
            }
            if (!Caps::of(cap).meet(forbidden_caps()).is_nothing()) {
                // refuse rather than silently ignore: a caller who asked for
                // CAP_SYS_ADMIN needs to know they are not getting it.
                std::fprintf(stderr,
                             "claybin-run: refusing to grant %.*s inside a sandbox\n",
                             static_cast<int>(cap_name(cap).size()), cap_name(cap).data());
                return 1;
            }
            policy = std::move(policy).keep_cap(cap);
            i += 1;
        } else if (std::strcmp(a, "--cap-drop") == 0) {
            if (!need(1, a)) return 1;
            if (strcasecmp_eq(eargv[i + 1], "ALL")) {
                policy = std::move(policy).drop_all_caps();
            } else {
                int cap = cap_from_name(eargv[i + 1]);
                if (cap < 0) {
                    std::fprintf(stderr, "claybin-run: unknown capability '%s'\n", eargv[i + 1]);
                    return 1;
                }
                policy = std::move(policy).drop_cap(cap);
            }
            i += 1;
        } else if (std::strcmp(a, "--as-pid-1") == 0) {
            policy = std::move(policy).as_pid_1();
        } else if (std::strcmp(a, "--exec-label") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).exec_label(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--file-label") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).file_label(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--chmod") == 0) {
            if (!need(2, a)) return 1;
            chmods.emplace_back(static_cast<std::uint32_t>(std::strtoul(eargv[i + 1], nullptr, 8)),
                                eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--lock-file") == 0) {
            if (!need(1, a)) return 1;
            lock_files.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--info-fd") == 0) {
            if (!need(1, a)) return 1;
            info_fd = static_cast<int>(std::strtol(eargv[i + 1], nullptr, 10));
            i += 1;
        } else if (std::strcmp(a, "--json-status-fd") == 0) {
            if (!need(1, a)) return 1;
            json_fd = static_cast<int>(std::strtol(eargv[i + 1], nullptr, 10));
            i += 1;
        } else if (std::strcmp(a, "--sync-fd") == 0) {
            if (!need(1, a)) return 1;
            sync_fd = static_cast<int>(std::strtol(eargv[i + 1], nullptr, 10));
            i += 1;
        } else if (std::strcmp(a, "--block-fd") == 0) {
            if (!need(1, a)) return 1;
            block_fd = static_cast<int>(std::strtol(eargv[i + 1], nullptr, 10));
            i += 1;
        } else if (std::strcmp(a, "--userns-block-fd") == 0) {
            if (!need(1, a)) return 1;
            userns_block_fd = static_cast<int>(std::strtol(eargv[i + 1], nullptr, 10));
            i += 1;
        } else if (std::strcmp(a, "--userns") == 0 || std::strcmp(a, "--userns2") == 0 ||
                   std::strcmp(a, "--pidns") == 0) {
            if (!need(1, a)) return 1;
            // joining an EXISTING namespace by fd. claybin creates its own, and
            // joining one it did not build means it cannot describe what the
            // guarantees are -- the whole report would be a guess. refuse.
            std::fprintf(stderr,
                         "claybin-run: %s not supported. claybin creates its own namespaces "
                         "so it can report what they actually enforce; joining one it did not "
                         "build would make the guarantee report a guess.\n", a);
            return 1;
        } else if (std::strcmp(a, "--disable-userns") == 0) {
            disable_nested_userns = true;
        } else if (std::strcmp(a, "--args") == 0) {
            if (!need(1, a)) return 1;
            // NUL-separated arguments from an fd. flatpak uses this to avoid
            // ARG_MAX and to keep paths with spaces intact. read the whole fd
            // and splice the results in at this position, so later command-line
            // flags still override earlier file ones.
            int fd = static_cast<int>(std::strtol(eargv[i + 1], nullptr, 10));
            std::string blob;
            char rb[4096];
            for (;;) {
                ssize_t n = ::read(fd, rb, sizeof rb);
                if (n <= 0) break;
                blob.append(rb, static_cast<std::size_t>(n));
            }
            ::close(fd);
            for (std::size_t p = 0; p < blob.size();) {
                std::size_t e = blob.find('\0', p);
                if (e == std::string::npos) e = blob.size();
                if (e > p) extra_args.push_back(blob.substr(p, e - p));
                p = e + 1;
            }
            args_fd = fd;
            i += 1;
        } else if (std::strcmp(a, "--allow-port") == 0) {
            if (!need(1, a)) return 1;
            // a claybin addition with no bubblewrap equivalent: grant TCP connect
            // to ONE port and let landlock enforce it. bwrap's --share-net is
            // all-or-nothing because a network namespace is all-or-nothing;
            // landlock (abi 4+) mediates per port, so this is a genuinely finer
            // boundary than the mount-namespace model can express.
            auto port = static_cast<std::uint16_t>(std::strtoul(eargv[i + 1], nullptr, 10));
            if (port == 0) {
                std::fprintf(stderr,
                             "claybin-run: --allow-port 0 means 'any port', which landlock "
                             "cannot enforce. use --share-net if that is what you want.\n");
                return 1;
            }
            policy = std::move(policy).connect("", port);
            i += 1;
        } else if (std::strcmp(a, "--allow-bind-port") == 0) {
            if (!need(1, a)) return 1;
            auto port = static_cast<std::uint16_t>(std::strtoul(eargv[i + 1], nullptr, 10));
            if (port == 0) {
                std::fprintf(stderr, "claybin-run: --allow-bind-port 0 is not enforceable\n");
                return 1;
            }
            policy = std::move(policy).bind_port(port);
            i += 1;
        } else if (std::strcmp(a, "--setenv") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).env(eargv[i + 1], eargv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--unsetenv") == 0) {
            if (!need(1, a)) return 1;
            unset_keys.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--clearenv") == 0) {
            // a fresh Draft is already env_cleared, so this is the default.
            // accepted for bwrap compatibility.
            clear_env = true;
        } else if (std::strcmp(a, "--overlay-src") == 0) {
            if (!need(1, a)) return 1;
            // bwrap's grammar: these ACCUMULATE and are consumed by the next
            // --overlay / --tmp-overlay / --ro-overlay. we buffer them here and
            // hand them to the builder as a required argument, so the library
            // never sees a layerless overlay.
            overlay_srcs.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--overlay") == 0) {
            if (!need(3, a)) return 1;
            if (overlay_srcs.empty()) {
                std::fprintf(stderr, "claybin-run: --overlay requires at least one "
                                     "--overlay-src\n");
                return 1;
            }
            policy = std::move(policy).overlay(overlay_srcs, eargv[i + 1], eargv[i + 2],
                                               eargv[i + 3]);
            overlay_srcs.clear();
            i += 3;
        } else if (std::strcmp(a, "--tmp-overlay") == 0) {
            if (!need(1, a)) return 1;
            if (overlay_srcs.empty()) {
                std::fprintf(stderr, "claybin-run: --tmp-overlay requires at least one "
                                     "--overlay-src\n");
                return 1;
            }
            policy = std::move(policy).tmp_overlay(overlay_srcs, eargv[i + 1]);
            overlay_srcs.clear();
            i += 1;
        } else if (std::strcmp(a, "--ro-overlay") == 0) {
            if (!need(1, a)) return 1;
            if (overlay_srcs.size() < 2) {
                std::fprintf(stderr, "claybin-run: --ro-overlay requires at least two "
                                     "--overlay-src\n");
                return 1;
            }
            policy = std::move(policy).ro_overlay(overlay_srcs, eargv[i + 1]);
            overlay_srcs.clear();
            i += 1;
        } else if (std::strcmp(a, "--share-net") == 0) {
            share_net = true;
        } else if (std::strcmp(a, "--unshare-all") == 0 ||
                   std::strncmp(a, "--unshare-", 10) == 0) {
            // unsharing everything is our default, so these are accepted and
            // ignored rather than rejected: a bwrap command line should work.
        } else if (std::strcmp(a, "--deny") == 0) {
            if (!need(1, a)) return 1;
            denies.push_back(eargv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--profile") == 0) {
            if (!need(1, a)) return 1;
            profile_name = eargv[i + 1];
            i += 1;
        } else if (std::strcmp(a, "--audit") == 0) {
            audit_only = true;
        } else if (std::strcmp(a, "--require") == 0) {
            if (!need(1, a)) return 1;
            const char* l = eargv[i + 1];
            require_level = std::strcmp(l, "strong") == 0    ? Enforcement::strong
                            : std::strcmp(l, "partial") == 0 ? Enforcement::partial
                                                             : Enforcement::advisory;
            i += 1;
        } else if (std::strcmp(a, "--not-a-security-boundary") == 0) {
            std::fprintf(stderr,
                         "claybin-run: refusing --not-a-security-boundary. a sandbox that "
                         "continues after a wall fails is not a sandbox.\n");
            return 1;
        } else {
            std::fprintf(stderr, "claybin-run: unknown option %s\n", a);
            return 1;
        }
    }

    if (!audit_only && i >= eargc) {
        std::fprintf(stderr, "claybin-run: no command given\n");
        return 1;
    }

    SyscallPolicy sys = std::strcmp(profile_name, "base") == 0   ? profiles::base()
                        : std::strcmp(profile_name, "proc") == 0 ? profiles::with_processes()
                        : std::strcmp(profile_name, "fs") == 0   ? profiles::with_filesystem()
                        : std::strcmp(profile_name, "net") == 0  ? profiles::with_network()
                        : std::strcmp(profile_name, "compiler-net") == 0
                            ? profiles::compiler_with_network()
                            : profiles::compiler();
    policy = std::move(policy).syscall_profile(sys);
    for (const auto& d : denies) policy = std::move(policy).deny(d);
    for (const auto& p : remount_ro) {
        // --remount-ro DEST means "whatever ends up at DEST, make it read-only".
        // as a landlock grant that is exactly a read-only subtree, which is
        // stronger than bwrap's version: bwrap only remounts, so a later bind
        // could shadow it, whereas a landlock rule survives any mount.
        policy = std::move(policy).grant(p, FileRights::exec());
    }
    if (new_session) policy = std::move(policy).new_session();
    if (die_with_parent) policy = std::move(policy).die_with_parent();
    if (share_net) policy = std::move(policy).connect("", 0);

    // bwrap INHERITS the environment unless --clearenv; the library defaults to
    // cleared, which is the safer default for a policy but the wrong one for a
    // drop-in replacement. so the CLI opts back in explicitly, and --clearenv
    // restores the library default.
    if (!clear_env) policy = std::move(policy).inherit_env();
    (void)inherit_env;

    auto sealed = std::move(policy).seal();
    auto compiled = compile(sealed, probe_host());
    if (!compiled) {
        std::fprintf(stderr, "claybin-run: %s (%.*s)\n",
                     to_string(compiled.error().code).data(),
                     static_cast<int>(compiled.error().mechanism.size()),
                     compiled.error().mechanism.data());
        return 1;
    }

    if (require_level != Enforcement::none) {
        auto ok = compiled->require(require_level,
                                    {CapId::fs_read, CapId::fs_write, CapId::syscall_filter,
                                     CapId::proc_isolation, CapId::privilege_drop});
        if (!ok) {
            std::fprintf(stderr, "claybin-run: host cannot enforce %.*s at %s\n",
                         static_cast<int>(ok.error().mechanism.size()),
                         ok.error().mechanism.data(), to_string(require_level));
            return 1;
        }
    }

    if (audit_only) {
        std::printf("PLAN  %zu ops, %zu bytes\n", compiled->plan.op_count(),
                    compiled->plan.size());
        compiled->plan.for_each([](OpCode c, std::span<const std::byte>) {
            std::printf("  %-10s %s\n", to_string(phase_of(c)), to_string(c));
            return true;
        });
        std::printf("\nGUARANTEES\n");
        for (std::size_t k = 0; k < kCapCount; ++k) {
            auto id = static_cast<CapId>(k);
            std::printf("  %-24s %-9s %s\n", cap_name(id),
                        to_string(compiled->guarantees.strength(id)),
                        compiled->guarantees.mechanism(id));
        }
        return 0;
    }

    // --lock-file: hold a shared flock for the sandbox's lifetime, so a caller
    // can tell whether any sandbox is still using a shared tree. taken BEFORE
    // the spawn and held by us, since the guest must not be able to release it.
    std::vector<int> held_locks;
    for (const auto& lf : lock_files) {
        int fd = ::open(lf.c_str(), O_RDONLY | O_CREAT | O_CLOEXEC, 0666);
        if (fd < 0) {
            std::fprintf(stderr, "claybin-run: --lock-file %s: %s\n", lf.c_str(),
                         std::strerror(errno));
            return 1;
        }
        struct flock fl{};
        fl.l_type = F_RDLCK;
        fl.l_whence = SEEK_SET;
        if (::fcntl(fd, F_SETLKW, &fl) < 0) {
            std::fprintf(stderr, "claybin-run: --lock-file %s: %s\n", lf.c_str(),
                         std::strerror(errno));
            return 1;
        }
        held_locks.push_back(fd);
    }

    // --chmod: applied to HOST paths before the sandbox exists, which is what
    // bwrap does. it mutates state outside the sandbox, so it is worth being
    // loud about rather than quiet.
    for (const auto& c : chmods) {
        if (::chmod(c.second.c_str(), static_cast<mode_t>(c.first)) < 0) {
            std::fprintf(stderr, "claybin-run: --chmod %o %s: %s\n", c.first,
                         c.second.c_str(), std::strerror(errno));
            return 1;
        }
    }

    // --block-fd: wait for the caller to say go. this is how a supervisor gets
    // to finish its own setup (cgroup placement, a seccomp notify listener)
    // before the guest runs.
    if (block_fd >= 0) {
        char c = 0;
        while (::read(block_fd, &c, 1) < 0 && errno == EINTR) {
        }
        ::close(block_fd);
    }

    std::vector<const char*> child_argv;
    for (int k = i; k < eargc; ++k) child_argv.push_back(eargv[k]);
    child_argv.push_back(nullptr);

    // --argv0 replaces what the program sees as its own name without changing
    // which binary we exec. shells and busybox-style multitools branch on it.
    const char* program = child_argv[0];
    if (argv0_override) child_argv[0] = argv0_override;
    (void)next_perms;

    // the environment is authority: PATH decides what gets executed and
    // LD_PRELOAD decides what code runs inside the guest. so the policy's env
    // is what the child gets, full stop -- a sealed policy that says
    // env_cleared must not have the parent's environment leak past it.
    //
    // this was a real bug: --setenv and --clearenv parsed fine and were then
    // ignored, because spawn() passed `environ` whenever envp was null.
    std::vector<std::string> env_storage;
    std::vector<const char*> child_env;
    for (const auto& e : sealed.data().env) {
        // --unsetenv wins over --setenv regardless of order on the command line.
        // bwrap applies them in sequence, but "unset" is the more restrictive
        // intent and letting a later --setenv resurrect a variable the caller
        // asked to drop would be the wrong direction to resolve a conflict.
        bool unset = false;
        for (const auto& u : unset_keys)
            if (u == e.key) { unset = true; break; }
        if (!unset) env_storage.push_back(e.key + "=" + e.value);
    }
    if (!sealed.data().env_cleared) {
        // not cleared: inherit, but let explicit --setenv win over the parent,
        // and honour --unsetenv.
        for (char** p = environ; p && *p; ++p) {
            std::string entry = *p;
            auto eq = entry.find('=');
            std::string key = eq == std::string::npos ? entry : entry.substr(0, eq);
            bool drop = false;
            for (const auto& e : sealed.data().env)
                if (e.key == key) { drop = true; break; }
            for (const auto& u : unset_keys)
                if (u == key) { drop = true; break; }
            if (!drop) env_storage.push_back(std::move(entry));
        }
    }
    for (const auto& s : env_storage) child_env.push_back(s.c_str());
    child_env.push_back(nullptr);

    Command cmd{program, child_argv.data(), child_env.data()};
    // spawn_in rather than spawn: the child is placed in its cgroup before it
    // execs, so the limits cover the target program's very first instruction.
    auto sp = spawn_in(compiled->plan, cmd, compiled->cgroup);
    if (!sp) {
        std::fprintf(stderr, "claybin-run: failed to start: %s (%.*s) errno=%d\n",
                     to_string(sp.error().code).data(),
                     static_cast<int>(sp.error().mechanism.size()), sp.error().mechanism.data(),
                     sp.error().sys_errno);
        return 1;
    }

    // --info-fd / --json-status-fd: tell the caller the sandbox's pid and the
    // mount namespace it ended up in, so a supervisor can watch it without
    // parsing our stderr. written as soon as we have a pid, before we wait, or a
    // caller reading synchronously would deadlock against us.
    //
    // the namespace id is the inode of /proc/PID/ns/mnt, which is how the kernel
    // identifies a namespace and how bwrap reports it.
    unsigned long long mnt_ns = 0;
    {
        char nspath[64];
        std::snprintf(nspath, sizeof nspath, "/proc/%d/ns/mnt", sp->pid);
        struct stat st{};
        if (::stat(nspath, &st) == 0) mnt_ns = st.st_ino;
    }
    if (info_fd >= 0) {
        char buf[256];
        int n = mnt_ns
                    ? std::snprintf(buf, sizeof buf,
                                    "{\n    \"child-pid\": %d,\n    \"mnt-namespace\": %llu\n}\n",
                                    sp->pid, mnt_ns)
                    : std::snprintf(buf, sizeof buf, "{\n    \"child-pid\": %d\n}\n", sp->pid);
        ssize_t w = ::write(info_fd, buf, static_cast<std::size_t>(n));
        (void)w;
        ::close(info_fd);
    }
    if (json_fd >= 0) {
        char buf[256];
        int n = mnt_ns ? std::snprintf(buf, sizeof buf,
                                       "{ \"child-pid\": %d, \"mnt-namespace\": %llu }\n",
                                       sp->pid, mnt_ns)
                       : std::snprintf(buf, sizeof buf, "{ \"child-pid\": %d }\n", sp->pid);
        ssize_t w = ::write(json_fd, buf, static_cast<std::size_t>(n));
        (void)w;
    }

    // --sync-fd: held open for the sandbox's lifetime and closed when it exits,
    // so a caller watching it for EOF learns the sandbox is gone without
    // needing to be our parent.
    (void)sync_fd;
    (void)userns_block_fd;
    (void)args_fd;
    (void)disable_nested_userns;

    int status = 0;
    ::waitpid(sp->pid, &status, 0);
    if (sp->pidfd >= 0) ::close(sp->pidfd);

    if (json_fd >= 0) {
        char buf[256];
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        int n = std::snprintf(buf, sizeof buf, "{ \"exit-code\": %d }\n", code);
        ssize_t w = ::write(json_fd, buf, static_cast<std::size_t>(n));
        (void)w;
        ::close(json_fd);
    }
    // releasing the locks here rather than leaking them makes the lifetime
    // exactly "while the sandbox runs", which is what a caller polling the lock
    // is asking about.
    for (int fd : held_locks) ::close(fd);
    if (sync_fd >= 0) ::close(sync_fd);

    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return WEXITSTATUS(status);
#endif
}
