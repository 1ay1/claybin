// claybin: linux capabilities as a lattice.
//
// a capability set is authority, so it is a Flags lattice like everything else:
// meet is intersection, and there is no public join. that matters more here than
// elsewhere, because `--cap-add` is the one bubblewrap flag that can only ever
// GRANT privilege -- so it lives on the Draft, where granting is explicit, and
// composing two sealed policies can never resurrect a capability either dropped.
//
// the name table is here because there is no libcap dependency: claybin emits
// its own prctl calls, so it needs its own CAP_* names.
#pragma once

#include <cstdint>
#include <string_view>

#include "claybin/core/lattice.hpp"

namespace clay {

struct CapsTag {};

// 64 bits is enough: CAP_LAST_CAP is 40 on 6.x kernels and the ABI reserves the
// rest. a bitset rather than a list, so meet is one AND.
class Caps : public Flags<CapsTag, std::uint64_t> {
    using Base = Flags<CapsTag, std::uint64_t>;

  public:
    using Base::Base;
    constexpr Caps(Base b) : Base(b) {}

    static constexpr Caps nothing() { return Caps{Base::nothing()}; }
    static constexpr Caps everything() { return Caps{Base::everything()}; }
    constexpr Caps meet(Caps o) const { return Caps{Base::meet(o)}; }

    static constexpr Caps of(int cap) { return Caps{std::uint64_t{1} << cap}; }
    constexpr bool has(int cap) const { return any(of(cap)); }
};

// the capability numbers we know about. hardcoded rather than pulled from
// linux/capability.h so this header builds anywhere and the values are visible
// at the point of use.
namespace cap_num {
inline constexpr int chown = 0;
inline constexpr int dac_override = 1;
inline constexpr int dac_read_search = 2;
inline constexpr int fowner = 3;
inline constexpr int fsetid = 4;
inline constexpr int kill = 5;
inline constexpr int setgid = 6;
inline constexpr int setuid = 7;
inline constexpr int setpcap = 8;
inline constexpr int linux_immutable = 9;
inline constexpr int net_bind_service = 10;
inline constexpr int net_broadcast = 11;
inline constexpr int net_admin = 12;
inline constexpr int net_raw = 13;
inline constexpr int ipc_lock = 14;
inline constexpr int ipc_owner = 15;
inline constexpr int sys_module = 16;
inline constexpr int sys_rawio = 17;
inline constexpr int sys_chroot = 18;
inline constexpr int sys_ptrace = 19;
inline constexpr int sys_pacct = 20;
inline constexpr int sys_admin = 21;
inline constexpr int sys_boot = 22;
inline constexpr int sys_nice = 23;
inline constexpr int sys_resource = 24;
inline constexpr int sys_time = 25;
inline constexpr int sys_tty_config = 26;
inline constexpr int mknod = 27;
inline constexpr int lease = 28;
inline constexpr int audit_write = 29;
inline constexpr int audit_control = 30;
inline constexpr int setfcap = 31;
inline constexpr int mac_override = 32;
inline constexpr int mac_admin = 33;
inline constexpr int syslog = 34;
inline constexpr int wake_alarm = 35;
inline constexpr int block_suspend = 36;
inline constexpr int audit_read = 37;
inline constexpr int perfmon = 38;
inline constexpr int bpf = 39;
inline constexpr int checkpoint_restore = 40;
inline constexpr int last = 40;
}  // namespace cap_num

// parse a CAP_* name, case-insensitively and with the prefix optional, matching
// libcap's cap_from_name(). returns -1 for an unknown name, so the caller can
// reject rather than silently granting nothing.
constexpr int cap_from_name(std::string_view n) {
    // strip an optional CAP_ / cap_ prefix
    if (n.size() > 4) {
        bool pre = (n[0] == 'C' || n[0] == 'c') && (n[1] == 'A' || n[1] == 'a') &&
                   (n[2] == 'P' || n[2] == 'p') && n[3] == '_';
        if (pre) n = n.substr(4);
    }
    auto eq = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            char x = a[i], y = b[i];
            if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
            if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
            if (x != y) return false;
        }
        return true;
    };

    struct Entry {
        std::string_view name;
        int value;
    };
    constexpr Entry table[] = {
        {"chown", cap_num::chown},
        {"dac_override", cap_num::dac_override},
        {"dac_read_search", cap_num::dac_read_search},
        {"fowner", cap_num::fowner},
        {"fsetid", cap_num::fsetid},
        {"kill", cap_num::kill},
        {"setgid", cap_num::setgid},
        {"setuid", cap_num::setuid},
        {"setpcap", cap_num::setpcap},
        {"linux_immutable", cap_num::linux_immutable},
        {"net_bind_service", cap_num::net_bind_service},
        {"net_broadcast", cap_num::net_broadcast},
        {"net_admin", cap_num::net_admin},
        {"net_raw", cap_num::net_raw},
        {"ipc_lock", cap_num::ipc_lock},
        {"ipc_owner", cap_num::ipc_owner},
        {"sys_module", cap_num::sys_module},
        {"sys_rawio", cap_num::sys_rawio},
        {"sys_chroot", cap_num::sys_chroot},
        {"sys_ptrace", cap_num::sys_ptrace},
        {"sys_pacct", cap_num::sys_pacct},
        {"sys_admin", cap_num::sys_admin},
        {"sys_boot", cap_num::sys_boot},
        {"sys_nice", cap_num::sys_nice},
        {"sys_resource", cap_num::sys_resource},
        {"sys_time", cap_num::sys_time},
        {"sys_tty_config", cap_num::sys_tty_config},
        {"mknod", cap_num::mknod},
        {"lease", cap_num::lease},
        {"audit_write", cap_num::audit_write},
        {"audit_control", cap_num::audit_control},
        {"setfcap", cap_num::setfcap},
        {"mac_override", cap_num::mac_override},
        {"mac_admin", cap_num::mac_admin},
        {"syslog", cap_num::syslog},
        {"wake_alarm", cap_num::wake_alarm},
        {"block_suspend", cap_num::block_suspend},
        {"audit_read", cap_num::audit_read},
        {"perfmon", cap_num::perfmon},
        {"bpf", cap_num::bpf},
        {"checkpoint_restore", cap_num::checkpoint_restore},
    };
    for (const auto& e : table)
        if (eq(n, e.name)) return e.value;
    return -1;
}

constexpr std::string_view cap_name(int cap) {
    switch (cap) {
        case cap_num::chown: return "CAP_CHOWN";
        case cap_num::dac_override: return "CAP_DAC_OVERRIDE";
        case cap_num::dac_read_search: return "CAP_DAC_READ_SEARCH";
        case cap_num::fowner: return "CAP_FOWNER";
        case cap_num::kill: return "CAP_KILL";
        case cap_num::setgid: return "CAP_SETGID";
        case cap_num::setuid: return "CAP_SETUID";
        case cap_num::setpcap: return "CAP_SETPCAP";
        case cap_num::net_bind_service: return "CAP_NET_BIND_SERVICE";
        case cap_num::net_admin: return "CAP_NET_ADMIN";
        case cap_num::net_raw: return "CAP_NET_RAW";
        case cap_num::sys_module: return "CAP_SYS_MODULE";
        case cap_num::sys_rawio: return "CAP_SYS_RAWIO";
        case cap_num::sys_chroot: return "CAP_SYS_CHROOT";
        case cap_num::sys_ptrace: return "CAP_SYS_PTRACE";
        case cap_num::sys_admin: return "CAP_SYS_ADMIN";
        case cap_num::sys_boot: return "CAP_SYS_BOOT";
        case cap_num::mknod: return "CAP_MKNOD";
        case cap_num::bpf: return "CAP_BPF";
        case cap_num::perfmon: return "CAP_PERFMON";
        default: return "CAP_?";
    }
}

// the ones that are escapes rather than conveniences. claybin refuses to grant
// these even when asked, because handing them to a sandboxed process defeats the
// sandbox outright and a caller who wants that does not need claybin.
constexpr Caps forbidden_caps() {
    return Caps{Caps::of(cap_num::sys_admin).bits() | Caps::of(cap_num::sys_module).bits() |
                Caps::of(cap_num::sys_rawio).bits() | Caps::of(cap_num::sys_ptrace).bits() |
                Caps::of(cap_num::sys_boot).bits() | Caps::of(cap_num::bpf).bits() |
                Caps::of(cap_num::perfmon).bits() | Caps::of(cap_num::mac_admin).bits() |
                Caps::of(cap_num::mac_override).bits() |
                Caps::of(cap_num::setpcap).bits()};
}

static_assert(Lattice<Caps>);

}  // namespace clay
