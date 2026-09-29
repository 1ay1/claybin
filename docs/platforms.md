# platform reality

the honest version, because a sandbox library that oversells its portability is
worse than one that only targets linux.

## what ports cleanly

the **policy algebra** is pure value types. no OS anywhere in it. `FsAuthority`,
`NetAuthority`, `ResourceLimits`, the lattice laws, the typestate, the guarantee
report: all of it compiles and tests identically on any platform with a c++23
compiler. that is most of the library by line count and essentially all of the
interesting design.

the **compile step** is a pure function of `(Policy, HostCapabilities)`, so a
new backend is a new `compile_for_X()` plus a new opcode set. nothing about the
front end changes.

## what does not port

### syscall filtering: linux only

seccomp has no equivalent anywhere else.

- **macOS** has no syscall filter available to unprivileged processes.
- **windows** has Process Mitigation Policies, which are a fixed menu of
  hardening switches (no dynamic code, no child processes, binary signature
  requirements), not arbitrary syscall filtering.

so `SyscallPolicy` compiles to nothing off linux and the report says
`syscall.filter: none`. that is not a gap to be papered over later; it is a real
difference in what the OS will do for you.

### the filesystem model differs, not just the API

this is the one that actually hurts.

- **linux landlock** and **macOS seatbelt** are both *path-prefix* models, so
  `FsAuthority`'s "grant a subtree, punch a hole" maps almost directly.
- **windows** is *ACL-on-object*. you do not grant "read `C:\workspace`
  recursively" to a process; you give the AppContainer's capability SID an ACE
  on specific objects. a recursive grant means walking and stamping DACLs, which
  is slow, mutates the host filesystem, and needs cleanup.

so `deny("/workspace/.git")` is one landlock rule on linux, one SBPL clause on
macOS, and a DACL edit on windows. same policy, three very different costs and
one of them has side effects on the host.

### resource limits

- **linux**: cgroup v2. the real thing.
- **windows**: job objects, genuinely comparable. memory, CPU, process count,
  all enforced per-job.
- **macOS**: rlimits only. no cgroup equivalent, so memory is `partial` forever.

windows is actually the *strongest* of the three here, which is a good reminder
that the ranking is per-capability, not per-OS.

## the matrix

what a policy compiles to, per capability, on a modern host:

| capability | linux | windows | macOS |
|---|---|---|---|
| filesystem read/write | strong (landlock) | partial (ACL/AppContainer) | strong (seatbelt) |
| filesystem exec | strong | partial | strong |
| network isolation | strong (netns) | partial (WFP/firewall) | partial (seatbelt) |
| process isolation | strong (pid ns) | strong (job object) | partial |
| syscall filter | strong (seccomp) | **none** | **none** |
| memory limit | strong (cgroup2) | strong (job object) | partial (rlimit) |
| pid limit | strong (cgroup2) | strong (job object) | partial (rlimit) |
| privilege drop | strong | strong (restricted token) | partial |
| device isolation | strong (devtmpfs) | partial | partial |
| host kernel isolation | **none** | **none** | **none** |

that last row is `none` everywhere for the process backend, by definition. only
a microvm backend changes it.

## so is it "easily cross-platform"?

**the API, yes. the security, no** — and pretending otherwise is the failure mode
this library was designed to avoid.

what makes it workable is that the difference is *reported rather than hidden*.
the same policy compiles everywhere, and `Compiled::guarantees` tells you
exactly which walls you actually got. a program that needs a syscall filter can
refuse to run on macOS instead of silently running unprotected.

that is what `Compiled::require()` is for:

```cpp
auto c = clay::compile(policy, clay::probe_host());
// on macOS this FAILS rather than running with no syscall filter
auto ok = c->require(Enforcement::strong, {CapId::fs_read, CapId::syscall_filter});
```

the portable *subset* is small: filesystem + process + resources. everything
beyond that is a per-platform decision the caller has to make explicitly.

## order of work

1. **linux first, properly.** it is the only platform where all the walls exist,
   so it is the only place the design can be validated end to end.
2. **windows second.** job objects and AppContainer are well documented and the
   model is genuinely strong; the filesystem translation is the real work.
3. **macOS third.** seatbelt is deprecated-but-universal (chrome still uses it),
   undocumented, and the App Sandbox alternative needs entitlements and code
   signing, which rules out sandboxing arbitrary binaries.

the backends are independent, so this order is a scheduling choice, not a
dependency chain.
