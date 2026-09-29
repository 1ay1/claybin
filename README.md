# claybin

an authority compiler for c++23. you describe what a process may do; claybin
turns that into the strongest set of kernel mechanisms the host can enforce,
and tells you honestly what it got.

it is **not** a runtime and it owns no loop. supervising a sandboxed process is
an event-loop job, and that job belongs to [jaal](https://github.com/1ay1/jaal).
see [docs/jaal.md](docs/jaal.md).

> **Status: early, and not ready to secure anything.** the policy algebra, the
> typestate and the seccomp compiler are built and tested. the mechanisms that
> actually enforce a policy — landlock, namespaces, cgroups — are not written
> yet, so today claybin can *describe* and *compile* a sandbox but cannot put
> one around a process. don't use it as a security boundary. it has not been
> audited or reviewed.

```cpp
#include <claybin/policy/policy.hpp>

using namespace clay;
using namespace clay::literals;

auto policy = Policy<Draft>{}
    .read("/usr")
    .read_write("/workspace")
    .memory(512_MB)
    .processes(64)
    .wall_clock(30_s)
    .seal();            // consumes the draft; nothing can widen it now

// composition is intersection. this can only ever be more restrictive.
auto tighter = policy & other_policy;
```

(that example is [a test](tests/readme_example_test.cpp), so it cannot drift
from the api.)

## why it is different

- **authority is a lattice.** composition is `meet`. there is no way to widen a
  sealed policy, because the widening operator does not exist.
- **typestate.** `Draft -> Sealed -> Plan`. a draft is consumed when sealed.
- **proof-carrying.** `Witness<Cap>` can only be minted by the backend that
  installed the mechanism. no backend is allowed to pretend.
- **fast by phase split.** all thinking happens ahead of the fork and compiles
  into a POD plan. the post-fork path is raw syscalls, zero allocation,
  async-signal-safe.
- **zero deps.** no libseccomp, no libcap, no libmount. we emit the BPF
  ourselves as a balanced interval tree, `O(log n)` per guest syscall.
- **no loop of its own.** claybin computes; something else waits. that keeps the
  whole library pure enough to unit-test on a machine with no seccomp at all.

see [docs/design.md](docs/design.md).

## build

no dependencies beyond a c++23 compiler and cmake.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## license

MIT
