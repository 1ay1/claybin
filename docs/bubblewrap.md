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

## what is missing

not yet implemented, and `--audit` will tell you so rather than pretending:

- `--seccomp FD` / `--add-seccomp-fd` (we compile our own; accepting a foreign
  BPF program is planned)
- `--uid` / `--gid` beyond identity mapping
- `--bind-data` / `--file` (writing a file from an fd into the sandbox)
- `--new-session` (setsid)
- `--userns` / `--pidns` (joining an existing namespace by fd)
- cgroup v2 limits, so `--audit` still reports memory and pids as `partial`

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
