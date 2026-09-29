# claybin and jaal

## the mistake this document fixes

the first draft of claybin called itself a "portable capability runtime" and
listed this as future work: process lifecycle, timeouts, pidfd readiness,
stdout/stderr pumping, seccomp notify brokering, an audit event stream.

that is an event loop. building it inside claybin would mean writing a second,
worse, less-tested version of jaal's kernel and hiding it under a security
library, where its bugs would be much harder to see.

jaal already has the hard parts done and conformance-tested on four reactors:
one message at a time, level-triggered readiness, re-subscribe between events,
bounded shutdown, faults contained, seeded replay.

so the split is:

    claybin   an authority COMPILER.  pure functions, no loop, no threads.
              policy -> IR -> bpf program / landlock ruleset / cgroup writes.

    jaal      the LOOP.  the supervisor is an ordinary jaal program.

## what "no loop" buys claybin

everything built so far is already loop-free, and that is not an accident. the
lattice, the typestate and the BPF emitter take values and return values, so:

- the seccomp emitter is unit-tested against a reference interpreter on any
  machine, including ones with no seccomp and no kernel headers
- policy composition is property-tested 45k times per run with no processes spawned
- `explain` and `audit` are pure queries over a compiled plan, so they work on a
  policy that was never installed anywhere

a library that owns a loop cannot do any of that without a live child process.

## the supervisor as a jaal program

the sandbox supervisor is a textbook Elm program: it has state (which children
are alive), messages (a child exited, a syscall wants brokering, a deadline
passed) and a pure decision function. sketch:

```cpp
struct Supervisor {
    struct Model {
        clay::Plan plan;                 // compiled once, reused per spawn
        std::vector<Running> children;
    };

    struct Spawned      { clay::Pid pid; };
    struct ChildExited  { clay::Pid pid; int status; };
    struct Broker       { clay::NotifyRequest req; };   // SECCOMP_RET_USER_NOTIF
    struct Deadline     { clay::Pid pid; };
    using Msg = std::variant<Spawned, ChildExited, Broker, Deadline>;

    // one reducer per case, pure, no waiting anywhere in here
    static Cmd update(Model& m, Broker b) {
        auto verdict = clay::broker::decide(m.plan, b.req);   // pure: policy lookup
        return Cmd::answer_notify(b.req.id, verdict);
    }
};
```

`clay::broker::decide` is the interesting one. deciding whether a brokered
`connect()` is allowed is a lookup in the compiled policy — pure, testable
without a kernel, and property-checkable against the lattice. the *waiting* on
the notify fd is a jaal source. the two never mix.

## the three integration points

### 1. `fx::spawn` — an effect

spawning is a command: data in, a Msg back later. the child's stdout/stderr are
ordinary fds the host watches, so claybin never touches an event loop.

```cpp
struct Spawn { const clay::Plan* plan; clay::Command cmd; };
using spawn = jaal::pure_fx<Spawn, "clay.spawn">;
```

### 2. pidfd — a source

`pidfd` is exactly what jaal's reactor concept wants: an fd that becomes
readable when the child dies. it is `cx.watch(pidfd, interest::read, token)`,
and level-triggered readiness means a missed wakeup is impossible rather than
merely unlikely. the ugly race in every hand-rolled supervisor (reap vs. close
vs. pid reuse) is a race jaal has already been made to handle.

### 3. the notify fd — a router

`SECCOMP_RET_USER_NOTIF` hands you an fd that becomes readable when the guest
makes a brokered syscall. that is a `router<NotifyEvent, "clay.notify">`, and
jaal's "route one event, re-subscribe, then route the next" rule matters here:
a policy change caused by one brokered syscall must be in effect for the next
one. that is the same bug class as maya's `^T m o` key-sequence bug, already
fixed once in jaal.

## what this means for testing

the payoff is bigger than tidiness.

a supervisor's genuinely hard bugs are races: reaping against pidfd close, a
notify arriving as the child exits, a timeout firing against a natural exit, two
children exiting in the same wakeup. "we wrote 400 escape tests" does not find
those; they are schedule-dependent and they reproduce once a week in CI.

`jaal::sim` and `explore()` drive a whole run from a seed with a fake clock. a
failing interleaving comes back with the seed that produced it and replays
exactly. so the escape suite tests the *policy* (does the wall hold), and the
simulator tests the *supervisor* (does the lifecycle hold), which are two
different questions that hand-written integration tests usually conflate.

## layering

claybin does not depend on jaal, and must not: the compiler is useful to anyone,
including a caller with their own loop, and the dependency would drag a thread
pool into a security library. the glue is a third thing.

    claybin          no jaal, no loop, no threads
    jaal             no claybin
    claybin-jaal     ~200 lines: effect descriptors + two sources

that also keeps claybin honest. if a feature cannot be expressed without
reaching for a loop, it belongs in the glue, not in the compiler.
