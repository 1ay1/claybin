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
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "claybin/plan/compile.hpp"
#include "claybin/plan/spawn.hpp"
#include "claybin/policy/profiles.hpp"

using namespace clay;

namespace {

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
                 "  --profile NAME         syscall profile: base|proc|fs|compiler\n"
                 "  --deny PATH            punch a landlock hole inside a bind\n"
                 "  --memory BYTES         memory cap (cgroup2 when available)\n"
                 "  --processes N          max processes (cgroup2 pids.max)\n"
                 "  --audit                print the guarantee report and exit\n"
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

    auto policy = Policy<Draft>{};
    bool share_net = false;
    bool audit_only = false;
    Enforcement require_level = Enforcement::none;
    std::uint64_t next_size = 0;
    const char* profile_name = "compiler";
    std::vector<std::string> denies;

    int i = 1;
    auto need = [&](int n, const char* what) -> bool {
        if (i + n >= argc) {
            std::fprintf(stderr, "claybin-run: %s needs %d argument(s)\n", what, n);
            return false;
        }
        return true;
    };

    for (; i < argc; ++i) {
        const char* a = argv[i];
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
            policy = std::move(policy).ro_bind(argv[i + 1], argv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--bind") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind(argv[i + 1], argv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--dev-bind") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).dev_bind(argv[i + 1], argv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--ro-bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(argv[i + 1], argv[i + 2], true);
            i += 2;
        } else if (std::strcmp(a, "--bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(argv[i + 1], argv[i + 2], false);
            i += 2;
        } else if (std::strcmp(a, "--dev-bind-try") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).bind_try(argv[i + 1], argv[i + 2], false);
            i += 2;
        } else if (std::strcmp(a, "--proc") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).proc_fs(argv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--dev") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).dev_fs(argv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--tmpfs") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).tmpfs(argv[i + 1],
                                             next_size ? Bytes{next_size} : Bytes::unlimited());
            next_size = 0;
            i += 1;
        } else if (std::strcmp(a, "--size") == 0) {
            if (!need(1, a)) return 1;
            next_size = std::strtoull(argv[i + 1], nullptr, 10);
            i += 1;
        } else if (std::strcmp(a, "--memory") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).memory(Bytes{std::strtoull(argv[i + 1], nullptr, 10)});
            i += 1;
        } else if (std::strcmp(a, "--processes") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).processes(std::strtoull(argv[i + 1], nullptr, 10));
            i += 1;
        } else if (std::strcmp(a, "--dir") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).mkdir(argv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--symlink") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).symlink(argv[i + 1], argv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--chdir") == 0) {
            if (!need(1, a)) return 1;
            policy = std::move(policy).workdir(argv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--hostname") == 0) {
            if (!need(1, a)) return 1;
            i += 1;  // accepted; the uts namespace already isolates it
        } else if (std::strcmp(a, "--setenv") == 0) {
            if (!need(2, a)) return 1;
            policy = std::move(policy).env(argv[i + 1], argv[i + 2]);
            i += 2;
        } else if (std::strcmp(a, "--share-net") == 0) {
            share_net = true;
        } else if (std::strcmp(a, "--unshare-all") == 0 ||
                   std::strncmp(a, "--unshare-", 10) == 0) {
            // unsharing everything is our default, so these are accepted and
            // ignored rather than rejected: a bwrap command line should work.
        } else if (std::strcmp(a, "--deny") == 0) {
            if (!need(1, a)) return 1;
            denies.push_back(argv[i + 1]);
            i += 1;
        } else if (std::strcmp(a, "--profile") == 0) {
            if (!need(1, a)) return 1;
            profile_name = argv[i + 1];
            i += 1;
        } else if (std::strcmp(a, "--audit") == 0) {
            audit_only = true;
        } else if (std::strcmp(a, "--require") == 0) {
            if (!need(1, a)) return 1;
            const char* l = argv[i + 1];
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

    if (!audit_only && i >= argc) {
        std::fprintf(stderr, "claybin-run: no command given\n");
        return 1;
    }

    SyscallPolicy sys = std::strcmp(profile_name, "base") == 0       ? profiles::base()
                        : std::strcmp(profile_name, "proc") == 0     ? profiles::with_processes()
                        : std::strcmp(profile_name, "fs") == 0       ? profiles::with_filesystem()
                                                                     : profiles::compiler();
    policy = std::move(policy).syscall_profile(sys);
    for (const auto& d : denies) policy = std::move(policy).deny(d);
    if (share_net) policy = std::move(policy).connect("", 0);

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

    std::vector<const char*> child_argv;
    for (int k = i; k < argc; ++k) child_argv.push_back(argv[k]);
    child_argv.push_back(nullptr);

    Command cmd{child_argv[0], child_argv.data(), nullptr};
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

    int status = 0;
    ::waitpid(sp->pid, &status, 0);
    if (sp->pidfd >= 0) ::close(sp->pidfd);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return WEXITSTATUS(status);
#endif
}
