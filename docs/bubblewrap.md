# replacing bubblewrap

claybin is meant to be a drop-in replacement for `bwrap`. the same command line
produces the same sandbox, and then adds walls bubblewrap does not have.

```sh
# identical output, identical tree
bwrap        --unshare-all --ro-bind /usr /usr --symlink usr/lib /lib \
             --proc /proc --dev /dev --tmpfs /tmp --chdir / -- /usr/bin/ls /
claybin-run  --unshare-all --ro-bind /usr /usr --symlink usr/lib /lib \
             --proc /proc --dev /dev --tmpfs /tmp --chdir / -- /usr/bin/ls /
```

## what is the same

the mount model, exactly: a private mount namespace, a tmpfs root assembled from
binds, `pivot_root` into it, old root detached. what is not mounted does not
exist inside the sandbox. flag names and argument order match, so an existing
invocation needs no edits.

## what claybin adds

| | bubblewrap | claybin |
|---|---|---|
| filesystem | mount namespace only | mount namespace **+ landlock** |
| syscall filter | only if you supply compiled BPF via `--seccomp` | on by default, from a named profile |
| filter cost | linear chain (libseccomp) | `O(log n)` interval tree |
| partial failure | `--not-a-security-boundary` continues | always refuses |
| what you got | no report | `--audit` prints per-capability enforcement |

the filesystem row is the substantive one. in bubblewrap a read-write bind is
fully writable, and the only way to narrow it is to not mount it. claybin emits
a landlock rule for every bind, so:

```sh
claybin-run --bind /workspace /workspace --deny /workspace/.git -- ./build.sh
```

`.git` is mounted (it is inside the bind) but landlock refuses access to it.
expressing that in bwrap needs a second bind of a tmpfs over `.git`, which is
both clumsier and weaker -- the guest can tell the difference and the empty
directory is writable.

the two mechanisms also fail differently, which is the point of running both: a
mount mistake makes a path invisible, a landlock mistake makes it inaccessible,
and an escape needs to beat both.

## conformance status

`tests/conformance.sh` runs the same invocation under `bwrap` and `claybin-run`
and requires identical guest-observable behaviour: same stdout, same exit code.
it is wired into ctest and skips itself when bwrap is not installed.

**36/36 passing** as of this writing, covering the tree layout (including hidden
entries, so no staging directory may leak), what must be unreachable, path
remapping, all three overlay kinds, env handling, try-variants, exit-code
fidelity, namespaces, and `--argv0`/`--new-session`/`--die-with-parent`.

stderr is deliberately not compared: the two tools word diagnostics differently
and always will. what has to match is what the *guest* sees.

### overlays

all three kinds work and match bwrap exactly:

| flag | upper layer | writes |
|---|---|---|
| `--overlay UP WORK DST` | the given directory | persist to the host |
| `--tmp-overlay DST` | a fresh tmpfs we mount | discarded at exit |
| `--ro-overlay DST` | none | refused (`EROFS`) |

two details cost real time and are worth writing down:

- **`userxattr` is mandatory in a user namespace.** without it overlayfs tries
  to use `trusted.*` xattrs, which need `CAP_SYS_ADMIN` in the *init* namespace,
  and the mount fails with a bare `EPERM`.
- **layer paths need escaping.** the layers are a `:`-separated list inside a
  comma-separated option string, so a path containing `:` or `,` silently
  becomes two layers. claybin escapes both.

the API differs from bwrap's here, deliberately. bwrap spells an overlay as
accumulated state — `--overlay-src A --overlay-src B --overlay UP WORK DST` —
and an `--overlay` with no preceding `--overlay-src` is an error it can only
catch at runtime. in the library the layers are a **required argument**, so an
overlay with no layers is not a representable state. the CLI still accepts
bwrap's spelling and buffers the sources before calling the builder.

## what reading the bubblewrap source fixed

these were real bugs in claybin, found by reading `bubblewrap.c` and
`bind-mount.c` rather than by testing. worth recording because each one is a
silent hole rather than a crash:

**1. a bind mount does not apply its flags.** `mount(src, dst, MS_BIND|MS_RDONLY)`
gives you a *writable* mount. you need a separate `MS_REMOUNT` pass. i had that
part right.

**2. but the remount only affects the top mount.** submounts keep their own
flags. so `--ro-bind /home /home` on a machine where `/home/x` is its own mount
left `/home/x` **writable**. claybin now parses `/proc/self/mountinfo` and
remounts every mount under the target. verified against bwrap with a real
submount: both refuse the write, and before the fix claybin allowed it.

**3. remount flags must be OR'd onto the existing ones.** remounting with only
our flags *drops* whatever was already there, so a mount that was `noexec`
becomes executable. tightening a mount by loosening it is a fine way to ship a
vulnerability.

**4. `MS_SLAVE`, not `MS_PRIVATE`.** slave still receives mounts from the host
but never propagates ours back. private cuts both directions, which sounds
tighter but means a long-running sandbox silently misses later host mounts and
sees a stale tree.

**5. the double pivot.** the obvious `pivot_root(newroot, oldroot)` leaves a
visible `/oldroot` in the guest's tree even after `MNT_DETACH`. bubblewrap does
it twice, the second time as `pivot_root(".", ".")` — put_old is allowed to be
the same directory as new_root, which stacks the old root on top of itself and
lets you detach it with **nothing left behind**. `ls -a /` is now byte-identical
to bwrap's.

**6. `newroot` must itself be a mount point** for that trick to work, so it gets
bind-mounted onto itself first. otherwise `pivot_root(".", ".")` is EINVAL, which
reads like nothing at all.

and two conformance bugs that were mine rather than subtle:

**7. the environment leaked entirely.** `--setenv` and `--clearenv` parsed fine
and were then ignored, because `spawn()` fell back to `environ` whenever `envp`
was null. the environment is authority — `PATH` decides what executes,
`LD_PRELOAD` decides what code runs — so this was a real hole, not a cosmetic
gap. the library still defaults to a cleared environment; the CLI opts back into
inheritance because that is what bwrap does.

**8. the syscall profiles could not run a shell.** missing `getpgrp` produced
`initialize_job_control: getpgrp failed: Success`, and missing `pipe2` produced
`pipe error: Operation not permitted` on any pipeline. libc prefers the modern
variants (`pipe2`, `dup3`, `openat`) and only falls back to the classic numbers
on ancient kernels, so an allow-list with just the classic ones looks correct
and fails in practice.

## what is still missing

**nothing, in the sense of flags.** all 68 of bubblewrap's options are handled:
59 explicitly and the 8 `--unshare-*` variants by prefix (an unknown flag still
errors, so the prefix match does not swallow typos). conformance is **51/51**.

what differs is behaviour in five places, and all five are claybin being
stricter on purpose. every one *refuses* rather than silently doing something
else, because a sandbox that quietly gives you less than you asked for is worse
than one that fails:

| flag | claybin | why |
|---|---|---|
| `--not-a-security-boundary` | refused | a sandbox that continues after a wall fails is not a sandbox |
| `--cap-add CAP_SYS_ADMIN` (and other escapes) | refused | `CAP_SYS_ADMIN` inside a sandbox means there is no sandbox |
| `--cap-add ALL` | refused | same, wholesale |
| `--seccomp FD` / `--add-seccomp-fd` | refused | claybin compiles its own filter; accepting the flag while running a *different* filter than the caller supplied is the worst available outcome. use `--profile`. |
| `--userns` / `--userns2` / `--pidns` | refused | joining a namespace claybin did not build makes the guarantee report a guess |

that last one is the interesting refusal. the others are about privilege; this
one is about honesty. the whole value of `Compiled::guarantees` is that it
describes walls claybin actually installed — if it inherits a namespace someone
else made, it has no idea what that namespace enforces, and every line of the
report becomes speculation.

two more are accepted but weaker than bwrap's version, and say so:

- `--exec-label` / `--file-label` are parsed and stored, but SELinux transitions
  are not applied. the report does not claim them.
- `--chmod` mutates a **host** path, like bwrap's. claybin does it because
  conformance demands it, but it is the one place a claybin policy has an effect
  outside the sandbox, which is worth knowing.

and one place claybin is genuinely better: `--mqueue` works. bubblewrap mounts it
before building `/dev` and fails with `EPERM` on an unprivileged user namespace;
claybin mounts it inside its own `/dev` tmpfs, where it is permitted, so the guest
gets a real message-queue filesystem. conformance asserts `stat -f` reports
`mqueue` rather than just matching bwrap's failure.

## the setuid question

bubblewrap can be installed setuid root, for kernels where unprivileged user
namespaces are disabled. claybin will not do this. a setuid binary is a much
larger attack surface than the thing it protects, and the distributions that
needed it have mostly enabled unprivileged userns since.

if `--audit` reports `process.isolation: none`, the host has userns disabled and
the answer is to enable it, not to add a setuid helper.

## porting a flatpak-style invocation

```sh
bwrap \
  --unshare-all --share-net \
  --ro-bind /usr /usr \
  --ro-bind /etc/resolv.conf /etc/resolv.conf \
  --bind "$HOME/.var/app/org.example" /home/user \
  --proc /proc --dev /dev --tmpfs /tmp \
  --chdir /home/user \
  -- /app/bin/thing
```

becomes the same thing with `claybin-run`, plus two additions worth making:

```sh
claybin-run \
  --unshare-all --share-net \
  --ro-bind /usr /usr \
  --ro-bind /etc/resolv.conf /etc/resolv.conf \
  --bind "$HOME/.var/app/org.example" /home/user \
  --proc /proc --dev /dev --tmpfs /tmp \
  --chdir /home/user \
  --deny /home/user/.ssh \
  --require strong \
  -- /app/bin/thing
```

`--deny` adds a landlock hole that has no bwrap equivalent. `--require strong`
makes the command fail on a host that cannot enforce every wall, instead of
running with fewer than you asked for.
