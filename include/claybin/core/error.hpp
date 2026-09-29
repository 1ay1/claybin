// claybin: error type. no exceptions anywhere in this library.
#pragma once

#include <cstdint>
#include <expected>
#include <string_view>

namespace clay {

enum class Errc : std::uint16_t {
    ok = 0,
    unsupported,         // the backend cannot express this capability at all
    kernel_too_old,      // mechanism exists but this kernel's abi is too old
    permission_denied,   // we lack the privilege to install the mechanism
    invalid_policy,      // the policy is self-contradictory or malformed
    path_too_long,       // a grant path exceeds the plan arena's bounds
    plan_overflow,       // the compiled plan exceeded its fixed arena
    too_many_rules,      // more rules than the mechanism can encode
    spawn_failed,        // clone/exec failed
    already_consumed,    // typestate violation caught at runtime
    io_error,
};

constexpr std::string_view to_string(Errc e) {
    switch (e) {
        case Errc::ok: return "ok";
        case Errc::unsupported: return "capability unsupported by backend";
        case Errc::kernel_too_old: return "kernel abi too old";
        case Errc::permission_denied: return "permission denied";
        case Errc::invalid_policy: return "invalid policy";
        case Errc::path_too_long: return "path too long";
        case Errc::plan_overflow: return "compiled plan overflow";
        case Errc::too_many_rules: return "too many rules";
        case Errc::spawn_failed: return "spawn failed";
        case Errc::already_consumed: return "object already consumed";
        case Errc::io_error: return "io error";
    }
    return "unknown";
}

// an error carries the failing mechanism and the raw errno, so audit output can
// say *which* wall failed rather than just "sandbox setup failed".
struct Error {
    Errc code{Errc::ok};
    std::string_view mechanism{};  // static string: "landlock", "seccomp", ...
    int sys_errno{0};

    constexpr Error() = default;
    constexpr Error(Errc c) : code(c) {}
    constexpr Error(Errc c, std::string_view m, int e = 0)
        : code(c), mechanism(m), sys_errno(e) {}

    friend constexpr bool operator==(const Error&, const Error&) = default;
};

template <class T>
using Result = std::expected<T, Error>;

using Status = std::expected<void, Error>;

}  // namespace clay
