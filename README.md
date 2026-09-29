# claybin

a portable capability runtime for c++23. sandboxing is one implementation of it.

status: early. the algebra, the typestate, and the seccomp compiler are real and
tested. the linux runtime is next.

```cpp
#include <claybin/policy/policy.hpp>

using namespace clay;
using namespace clay::literals;

auto policy = Policy{}
    .read("/usr")
    .read_write("/workspace")
    .memory(512_MB)
    .processes(64)
    .wall_clock(30_s)
    .seal();

// composition is intersection. this can only ever be more restrictive.
auto tighter = policy & profiles::minimal();
```

## why it is different

- **authority is a lattice.** composition is `meet`. there is no way to widen a
  sealed policy, because the widening operator does not exist.
- **typestate.** `Draft -> Sealed -> Plan -> Child`. a draft is consumed when
  sealed, a child is move-only and reaps itself.
- **proof-carrying.** `Witness<Cap>` can only be minted by the backend that
  installed the mechanism. no backend is allowed to pretend.
- **fast by phase split.** all thinking happens pre-fork into a POD plan. the
  post-fork path is raw syscalls, zero allocation, async-signal-safe.
- **zero deps.** no libseccomp, no libcap, no libmount. we emit the BPF
  ourselves as a balanced interval tree, `O(log n)` per guest syscall.

see [docs/design.md](docs/design.md).

## build

```sh
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
```
