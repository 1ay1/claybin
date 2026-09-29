#!/bin/sh
# differential conformance: run the same invocation under bwrap and claybin-run
# and require identical observable behaviour.
#
# this is the only honest way to claim "drop-in replacement". a flag-by-flag
# checklist proves nothing about semantics; running both and diffing does.
#
# usage: tests/conformance.sh [path-to-claybin-run]

set -u
CLAY="${1:-./build/claybin-run}"
BWRAP="$(command -v bwrap || true)"

if [ -z "$BWRAP" ]; then
    echo "skip: bwrap not installed, nothing to compare against"
    exit 0
fi
if [ ! -x "$CLAY" ]; then
    echo "FAIL: $CLAY not found or not executable"
    exit 1
fi

PASS=0
FAIL=0
SKIP=0

# the loader bits every dynamically linked guest needs. kept in one place so a
# case only states what it is actually testing.
BASE="--ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin"

# run one case under both tools and compare stdout+exit code.
#
# stderr is deliberately NOT compared: the two tools word their diagnostics
# differently and always will. what has to match is what the GUEST observes.
#
# note each tool gets its OWN invocation of the redirect, which matters for the
# fd-passing cases: a shared fd would be left at EOF by whichever tool ran
# first, and the second would faithfully copy zero bytes. that bit me.
check() {
    desc="$1"; shift
    b_out=$($BWRAP "$@" 2>/dev/null); b_rc=$?
    c_out=$($CLAY  "$@" 2>/dev/null); c_rc=$?

    if [ "$b_out" = "$c_out" ] && [ "$b_rc" = "$c_rc" ]; then
        PASS=$((PASS+1))
        printf '  ok    %s\n' "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL  %s\n' "$desc"
        printf '          bwrap  rc=%s out=[%s]\n' "$b_rc" "$(echo "$b_out" | tr '\n' '|')"
        printf '          clay   rc=%s out=[%s]\n' "$c_rc" "$(echo "$c_out" | tr '\n' '|')"
    fi
}

# same, but each tool gets a freshly-opened fd 9 on $2. needed because reading
# an fd CONSUMES it: sharing one between the two runs left the second tool at
# EOF, and it faithfully copied zero bytes.
check_fd() {
    desc="$1"; fdfile="$2"; shift 2
    b_out=$($BWRAP "$@" 9<"$fdfile" 2>/dev/null); b_rc=$?
    c_out=$($CLAY  "$@" 9<"$fdfile" 2>/dev/null); c_rc=$?

    if [ "$b_out" = "$c_out" ] && [ "$b_rc" = "$c_rc" ]; then
        PASS=$((PASS+1))
        printf '  ok    %s\n' "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL  %s\n' "$desc"
        printf '          bwrap  rc=%s out=[%s]\n' "$b_rc" "$(echo "$b_out" | tr '\n' '|')"
        printf '          clay   rc=%s out=[%s]\n' "$c_rc" "$(echo "$c_out" | tr '\n' '|')"
    fi
}

# a case claybin is expected to REFUSE where bwrap allows it. claybin is
# deliberately stricter in a few places, and pretending otherwise would be the
# same dishonesty the library exists to avoid -- so those are asserted, not
# smoothed over.
check_stricter() {
    desc="$1"; shift
    $BWRAP "$@" >/dev/null 2>&1; b_rc=$?
    $CLAY  "$@" >/dev/null 2>&1; c_rc=$?
    if [ "$b_rc" -eq 0 ] && [ "$c_rc" -ne 0 ]; then
        PASS=$((PASS+1))
        printf '  ok    %s (claybin refuses, by design)\n' "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL  %s: expected bwrap=0 clay!=0, got bwrap=%s clay=%s\n' \
               "$desc" "$b_rc" "$c_rc"
    fi
}

echo "conformance: $CLAY vs $BWRAP"
echo

# ---- the tree ----------------------------------------------------------------
check "ro-bind /usr, ls /" \
    $BASE --chdir / -- /usr/bin/ls /
check "ls -a / (no oldroot leak)" \
    $BASE --chdir / -- /usr/bin/ls -a /
check "proc mounted" \
    $BASE --proc /proc --chdir / -- /usr/bin/ls /proc/self
check "dev mounted" \
    $BASE --dev /dev --chdir / -- /usr/bin/ls /dev
check "tmpfs is writable" \
    $BASE --tmpfs /tmp --chdir / -- /bin/sh -c 'echo hi > /tmp/x && cat /tmp/x'
check "full flatpak shape" \
    --unshare-all $BASE --proc /proc --dev /dev --tmpfs /tmp --chdir / -- /usr/bin/ls /

# ---- what must NOT be reachable ---------------------------------------------
check "host /etc is absent" \
    $BASE --chdir / -- /usr/bin/test -e /etc
check "host /home is absent" \
    $BASE --chdir / -- /usr/bin/test -e /home
check "ro-bind rejects writes" \
    $BASE --chdir / -- /usr/bin/touch /usr/probe
check "/dev/mem absent from --dev" \
    $BASE --dev /dev --chdir / -- /usr/bin/test -e /dev/mem

# ---- remapping, the mount model's whole point -------------------------------
check "bind remaps a path" \
    $BASE --ro-bind /usr/share /data --chdir / -- /usr/bin/test -d /data
check "symlink is created" \
    $BASE --symlink usr/share /shared --chdir / -- /usr/bin/test -L /shared
check "dir is created" \
    $BASE --dir /workspace --chdir / -- /usr/bin/test -d /workspace
check "chdir takes effect" \
    $BASE --chdir /usr -- /usr/bin/pwd

# ---- env --------------------------------------------------------------------
check "setenv" \
    $BASE --setenv CLAY_TEST value1 --chdir / -- /bin/sh -c 'echo $CLAY_TEST'
check "clearenv drops the environment" \
    $BASE --clearenv --chdir / -- /bin/sh -c 'echo "[$HOME]"'

# ---- try-variants -----------------------------------------------------------
check "ro-bind-try on a missing source" \
    $BASE --ro-bind-try /nonexistent-xyz /target --chdir / -- /usr/bin/ls /
check "bind-try on a missing source" \
    $BASE --bind-try /nonexistent-xyz /target --chdir / -- /usr/bin/ls /

# ---- exit-code fidelity -----------------------------------------------------
check "guest exit code 0" \
    $BASE --chdir / -- /usr/bin/true
check "guest exit code 1" \
    $BASE --chdir / -- /usr/bin/false
check "guest exit code 42" \
    $BASE --chdir / -- /bin/sh -c 'exit 42'
check "exec failure is reported" \
    $BASE --chdir / -- /usr/bin/definitely-not-a-real-binary

# ---- namespaces -------------------------------------------------------------
check "unshare-net kills connectivity" \
    $BASE --unshare-net --chdir / -- /bin/sh -c 'ls /sys/class/net 2>/dev/null | wc -l'
check "unshare-pid gives us a fresh pid space" \
    $BASE --unshare-pid --proc /proc --chdir / -- /bin/sh -c 'ls /proc | grep -c "^1$"'

# ---- overlays ----------------------------------------------------------------
# these need scratch directories, so they are set up and torn down here rather
# than assumed to exist.
OVL_LOWER=$(mktemp -d)
OVL_LOWER2=$(mktemp -d)
OVL_UPPER=$(mktemp -d)
OVL_WORK=$(mktemp -d)
echo "from-lower" > "$OVL_LOWER/a.txt"
echo "from-lower2" > "$OVL_LOWER2/b.txt"

check "tmp-overlay reads the lower layer" \
    $BASE --overlay-src "$OVL_LOWER" --tmp-overlay /data --chdir / \
    -- /bin/sh -c 'cat /data/a.txt'
check "tmp-overlay accepts writes" \
    $BASE --overlay-src "$OVL_LOWER" --tmp-overlay /data --chdir / \
    -- /bin/sh -c 'echo x > /data/new && ls /data'
check "ro-overlay merges two layers" \
    $BASE --overlay-src "$OVL_LOWER" --overlay-src "$OVL_LOWER2" --ro-overlay /data \
    --chdir / -- /usr/bin/ls /data
check "ro-overlay rejects writes" \
    $BASE --overlay-src "$OVL_LOWER" --overlay-src "$OVL_LOWER2" --ro-overlay /data \
    --chdir / -- /usr/bin/touch /data/x
check "writable overlay merges" \
    $BASE --bind "$OVL_UPPER" "$OVL_UPPER" --bind "$OVL_WORK" "$OVL_WORK" \
    --overlay-src "$OVL_LOWER" --overlay "$OVL_UPPER" "$OVL_WORK" /data \
    --chdir / -- /usr/bin/ls /data

# the tmp-overlay's whole point: the host must be untouched afterwards.
$CLAY $BASE --overlay-src "$OVL_LOWER" --tmp-overlay /data --chdir / \
    -- /bin/sh -c 'echo leaked > /data/leaked.txt' >/dev/null 2>&1
if [ -e "$OVL_LOWER/leaked.txt" ]; then
    FAIL=$((FAIL+1))
    printf '  FAIL  tmp-overlay leaked a write to the host lower layer\n'
else
    PASS=$((PASS+1))
    printf '  ok    tmp-overlay discards writes (host untouched)\n'
fi

rm -rf "$OVL_LOWER" "$OVL_LOWER2" "$OVL_UPPER" "$OVL_WORK"

# ---- the newer flags ---------------------------------------------------------
check "argv0 override" \
    $BASE --argv0 myname --chdir / -- /bin/sh -c 'echo $0'
check "new-session" \
    $BASE --new-session --chdir / -- /usr/bin/true
check "die-with-parent" \
    $BASE --die-with-parent --chdir / -- /usr/bin/true
check "hostname is accepted" \
    $BASE --unshare-uts --hostname sandbox1 --chdir / -- /usr/bin/true
check "unsetenv" \
    $BASE --setenv KEEP yes --setenv DROP no --unsetenv DROP --chdir / \
    -- /bin/sh -c 'echo "$KEEP-$DROP"'

# ---- fd passing --------------------------------------------------------------
# an fd names an object rather than a path. these are the flags flatpak's own
# supervisor uses, because it already holds descriptors it does not want to
# re-resolve by name.
FD_DATA=$(mktemp)
echo "content-from-fd" > "$FD_DATA"

check_fd "file from fd" "$FD_DATA" \
    $BASE --file 9 /data.txt --chdir / -- /usr/bin/cat /data.txt
check_fd "bind-data from fd" "$FD_DATA" \
    $BASE --bind-data 9 /d.txt --chdir / -- /usr/bin/cat /d.txt
check_fd "ro-bind-data rejects writes" "$FD_DATA" \
    $BASE --ro-bind-data 9 /d.txt --chdir / \
    -- /bin/sh -c 'cat /d.txt; echo x > /d.txt'
check_fd "ro-bind-fd binds a directory" /usr/share \
    $BASE --ro-bind-fd 9 /shared --chdir / -- /usr/bin/test -d /shared
check_fd "bind-fd contents are real" /usr/share \
    $BASE --ro-bind-fd 9 /shared --chdir / -- /bin/sh -c 'ls /shared | head -1'

# --bind-data must leave NO other path to the content. the backing file is
# unlinked after the bind, so /tmp inside the sandbox must not contain it.
$CLAY $BASE --bind-data 9 /d.txt --tmpfs /scratch --chdir / \
    -- /bin/sh -c 'ls /tmp 2>/dev/null | grep -c bindfile' 9<"$FD_DATA" >/tmp/clay_bd.out 2>&1
if grep -q '^0$' /tmp/clay_bd.out 2>/dev/null || [ ! -s /tmp/clay_bd.out ]; then
    PASS=$((PASS+1))
    printf '  ok    bind-data backing file is unlinked\n'
else
    FAIL=$((FAIL+1))
    printf '  FAIL  bind-data left its backing file reachable\n'
fi
rm -f /tmp/clay_bd.out "$FD_DATA"

# ---- identity, capabilities, status ------------------------------------------
check "uid 0 inside the namespace" \
    $BASE --uid 0 --gid 0 --chdir / -- /usr/bin/id -u
check "cap-drop ALL" \
    $BASE --cap-drop ALL --chdir / -- /usr/bin/true
check "cap-add NET_BIND_SERVICE" \
    $BASE --cap-add CAP_NET_BIND_SERVICE --chdir / -- /usr/bin/true
check "as-pid-1" \
    $BASE --unshare-pid --as-pid-1 --proc /proc --chdir / -- /usr/bin/true
# mqueue is one place claybin is genuinely BETTER, so it cannot be a `check`.
# bwrap mounts it before building /dev and fails with EPERM on an unprivileged
# userns; claybin mounts it inside its own /dev tmpfs, where it is permitted, and
# the guest gets a real message-queue filesystem. asserted directly.
mq=$($CLAY $BASE --dev /dev --mqueue /dev/mqueue --chdir / \
     -- /usr/bin/stat -f -c '%T' /dev/mqueue 2>/dev/null)
if [ "$mq" = "mqueue" ]; then
    PASS=$((PASS+1))
    printf '  ok    mqueue is a real mqueue fs (bwrap fails here)\n'
else
    FAIL=$((FAIL+1))
    printf '  FAIL  mqueue: expected a mqueue fs, got [%s]\n' "$mq"
fi

# --args: NUL-separated arguments read from an fd, spliced in as if typed.
ARGS_BIN=$(mktemp)
printf '%s\0%s\0%s\0' "--ro-bind" "/usr" "/usr" > "$ARGS_BIN"
check_fd "args from fd" "$ARGS_BIN" \
    --args 9 --symlink usr/lib /lib --symlink usr/lib64 /lib64 --chdir / -- /usr/bin/true
rm -f "$ARGS_BIN"

# the JSON status shape has to match field-for-field, since a supervisor parses
# it. the ids themselves differ per run, so compare with numbers normalized.
b_json=$($BWRAP $BASE --json-status-fd 3 --chdir / -- /bin/sh -c 'exit 7' \
         3>&1 >/dev/null 2>/dev/null | sed 's/[0-9]\+/N/g' | tr -d '\n')
c_json=$($CLAY  $BASE --json-status-fd 3 --chdir / -- /bin/sh -c 'exit 7' \
         3>&1 >/dev/null 2>/dev/null | sed 's/[0-9]\+/N/g' | tr -d '\n')
if [ "$b_json" = "$c_json" ]; then
    PASS=$((PASS+1))
    printf '  ok    json-status-fd shape matches\n'
else
    FAIL=$((FAIL+1))
    printf '  FAIL  json-status-fd shape differs\n'
    printf '          bwrap  %s\n' "$b_json"
    printf '          clay   %s\n' "$c_json"
fi

# ---- claybin is deliberately stricter ---------------------------------------
check_stricter "--not-a-security-boundary" \
    $BASE --not-a-security-boundary --chdir / -- /usr/bin/true
check_stricter "--cap-add CAP_SYS_ADMIN" \
    $BASE --cap-add CAP_SYS_ADMIN --chdir / -- /usr/bin/true
check_stricter "--cap-add ALL" \
    $BASE --cap-add ALL --chdir / -- /usr/bin/true

echo
echo "pass=$PASS fail=$FAIL skip=$SKIP"
[ "$FAIL" -eq 0 ]
