#!/bin/sh
# audit the aarch64 syscall tables against the kernel's own header.
#
# this exists because those tables have never EXECUTED. there is no aarch64
# hardware here and no cross toolchain, so syscall_table_test compiles them and
# checks the numbers it was told to check -- which shares an author, and
# therefore a possible misreading, with the tables themselves.
#
# this script is the independent half: it dumps what the compiled profiles
# actually permit and cross-checks every number against <asm-generic/unistd.h>,
# which is the table aarch64 really uses. a wrong number shows up either as a
# name that should never be allowed, or as a number that names nothing at all.
#
# usage: aarch64_audit.sh <path-to-dumparm-binary>
set -e

DUMP="${1:-}"
if [ -z "$DUMP" ] || [ ! -x "$DUMP" ]; then
    echo "skip aarch64_audit: no dump binary (pass \$<TARGET_FILE:clay_dump_aarch64>)"
    exit 0
fi
HDR=/usr/include/asm-generic/unistd.h
if [ ! -r "$HDR" ]; then
    echo "skip aarch64_audit: $HDR not readable"
    exit 0
fi

"$DUMP" > /tmp/clay-armdump.$$ || { echo "FAIL aarch64_audit: dump failed"; exit 1; }

python3 - "$HDR" /tmp/clay-armdump.$$ <<'PY'
import re, sys, collections

hdr, dump = sys.argv[1], sys.argv[2]

gen = {}
for line in open(hdr):
    m = re.match(r'#define __NR_(\w+)\s+(\d+)\s*$', line)
    if m:
        gen[m.group(1)] = int(m.group(2))
for line in open(hdr):
    m = re.match(r'#define __NR3264_(\w+)\s+(\d+)\s*$', line)
    if m:
        gen.setdefault(m.group(1), int(m.group(2)))

rev = collections.defaultdict(list)
for k, v in gen.items():
    rev[v].append(k)

# syscalls that must never be permitted inside a sandbox. by NAME, resolved
# through the header -- the whole point is not to trust a number.
FORBIDDEN = {
    'ptrace', 'mount', 'umount2', 'pivot_root', 'chroot', 'unshare', 'setns',
    'bpf', 'perf_event_open', 'init_module', 'delete_module', 'finit_module',
    'kexec_load', 'kexec_file_load', 'reboot', 'setfsuid', 'setfsgid',
    'open_by_handle_at', 'process_vm_readv', 'process_vm_writev', 'pidfd_getfd',
    'userfaultfd', 'io_uring_setup', 'add_key', 'request_key', 'keyctl',
    'syslog', 'acct', 'swapon', 'swapoff', 'quotactl', 'clone3',
}

rows = collections.defaultdict(dict)
for line in open(dump):
    parts = line.split()
    if len(parts) != 3:
        continue
    prof, act, nr = parts
    rows[prof][int(nr)] = act

if not rows:
    print("FAIL aarch64_audit: dump produced no rows")
    sys.exit(1)

bad, unknown = [], []
for prof, tbl in rows.items():
    for nr, act in tbl.items():
        if act != 'ALLOW':
            continue
        names = rev.get(nr, [])
        if not names:
            unknown.append((prof, nr))
        elif FORBIDDEN & set(names):
            bad.append((prof, nr, names))

allows = sum(1 for t in rows.values() for a in t.values() if a == 'ALLOW')
kills = sum(1 for t in rows.values() for a in t.values() if a == 'KILL')

fail = False
if bad:
    print("FAIL aarch64_audit: forbidden syscall permitted")
    for p, n, names in sorted(bad):
        print(f"    {p}: nr {n} is {names}")
    fail = True
if unknown:
    print("FAIL aarch64_audit: permitted number is not an aarch64 syscall")
    for p, n in sorted(set(unknown)):
        print(f"    {p}: nr {n} names nothing in the header")
    fail = True

if fail:
    sys.exit(1)

print(f"ok aarch64_audit ({len(rows)} profiles, {allows} allow / {kills} kill "
      f"entries cross-checked against the kernel header)")
PY
rc=$?
rm -f /tmp/clay-armdump.$$
exit $rc
