# claybin

a drop-in replacement for [bubblewrap](https://github.com/containers/bubblewrap),
and the authority compiler underneath it.

```sh
# same flags, same resulting tree
bwrap        --unshare-all --ro-bind /usr /usr --proc /proc --dev /dev \
             --tmpfs /tmp --chdir / -- /usr/bin/ls /
claybin-run  --unshare-all --ro-bind /usr /usr --proc /proc --dev /dev \
             --tmpfs /tmp --chdir / -- /usr/bin/ls /
```

the difference is what happens underneath. bubblewrap gives you a mount
namespace; claybin gives you a mount namespace **and** a landlock ruleset **and**
a seccomp filter compiled from the same description, plus a report of exactly
which walls the host could actually build.

see [docs/bubblewrap.md](docs/bubblewrap.md) for the porting guide.

it owns no event loop. supervising a sandboxed process is an event-loop job, and
that job belongs to [jaal](https://github.com/1ay1/jaal) — see
[docs/jaal.md](docs/jaal.md).

> **Status: early.** the mount model, landlock, seccomp and the policy algebra
> work and are tested, including an escape suite that spawns real processes and
> tries to break out. cgroup limits are not implemented yet, so resource caps
> report as `partial`. it has not been audited or reviewed by anyone but me.

## the library underneath

```cpp
#include <claybin/policy/policy.hpp>

using namespace clay;
using namespace clay::literals;

auto policy = Policy<Draft>{}
    .ro_bind("/usr", "/usr")        // build a tree, bubblewrap-style
    .bind("/workspace", "/work")
    .deny("/work/.git")             // ...and punch a landlock hole in it
    .tmpfs("/tmp", 64_MB)
    .memory(512_MB)
    .syscall_profile(profiles::compiler())
    .seal();                        // consumes the draft; nothing can widen it

auto compiled = compile(policy, probe_host());
auto ok = compiled->require(Enforcement::strong, {CapId::fs_read, CapId::syscall_filter});
```

## why it is different

- **two independent filesystem walls.** every bind emits a landlock rule, so a
  path is checked by the mount namespace *and* by landlock. an escape has to
  beat both, and they fail in different directions.
- **authority is a lattice.** composition is `meet`. there is no way to widen a
  sealed policy, because the widening operator does not exist.
- **proof-carrying.** `Witness<Cap>` can only be minted by the backend that
  installed the mechanism. no backend is allowed to pretend.
- **it refuses rather than degrades.** bubblewrap has
  `--not-a-security-boundary`; claybin fails instead.
- **fast by phase split.** all thinking happens ahead of the fork and compiles
  into a POD plan. the post-fork path is raw syscalls, zero allocation,
  async-signal-safe.
- **zero deps.** no libseccomp, no libcap, no libmount. the BPF is a balanced
  interval tree, `O(log n)` per guest syscall instead of a linear chain.

see [docs/design.md](docs/design.md), and
[docs/platforms.md](docs/platforms.md) for what does and does not port off
linux.

## build

no dependencies beyond a c++23 compiler and cmake.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## license

MIT
