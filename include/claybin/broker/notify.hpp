// claybin: seccomp user-notification brokering.
//
// this is the piece that makes a sandbox a CAPABILITY SYSTEM rather than a
// filter. SECCOMP_RET_USER_NOTIF hands a blocked syscall to a userspace
// supervisor, which decides -- at runtime, with the arguments in hand -- whether
// to allow it, deny it, or perform it on the guest's behalf and pass back the
// result.
//
// what that buys, concretely: a guest can be given "you may reach
// api.github.com:443" rather than "you may call connect()". the supervisor
// resolves the name ITSELF and hands back a connected descriptor, so DNS
// rebinding cannot widen the grant after the check -- there is no second lookup
// for an attacker to poison.
//
// THE PART EVERY IMPLEMENTATION GETS WRONG, stated up front. a notification
// carries the syscall's REGISTER arguments. a pointer argument names memory in
// the guest, and the guest has other threads: it can rewrite that memory between
// the moment the supervisor reads it and the moment the kernel acts on it. so
// reading a path or a sockaddr out of the guest and then approving the syscall is
// a TOCTOU vulnerability, not a feature.
//
// the kernel's answer is SECCOMP_IOCTL_NOTIF_ADDFD plus an explicit validity
// check: the supervisor must re-verify the notification is still live -- the
// guest thread alive, the id not reused -- immediately before responding.
// claybin therefore supports exactly two shapes of decision:
//
//   scalar-only           decide from register values alone. sound, always.
//   supervisor-performs   the supervisor does the work and injects a descriptor;
//                         the guest never dereferences anything on our behalf.
//
// deliberately NOT supported: "read a string out of the guest, validate it, then
// allow the syscall". that is the unsound pattern, and offering it would be worse
// than having no broker at all.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>

#include "claybin/core/error.hpp"
#include "claybin/core/fd.hpp"
#include "claybin/policy/syscalls.hpp"

namespace clay::broker {

// one syscall the guest attempted, as the kernel described it.
//
// only the scalar registers are here, on purpose: there is no `path` field,
// because providing one would invite the unsound pattern above.
struct Request {
    std::uint64_t id{0};      // the notification id, needed to respond
    std::uint32_t pid{0};     // the guest thread
    SysNr nr{0};              // which syscall
    std::uint64_t args[6]{};  // its register arguments, verbatim
};

// what the supervisor decided.
struct Decision {
    enum class Kind : std::uint8_t {
        // let the kernel run the syscall as the guest wrote it. only sound when
        // the decision used scalar arguments alone.
        allow,
        // fail it with an errno. always sound.
        deny,
        // the supervisor already did the work; `injected_fd` becomes the
        // syscall's return value in the guest. this is the shape that makes
        // brokering safe for anything involving a pointer.
        inject_fd,
    };

    Kind kind{Kind::deny};
    int error{1};            // deny: the errno to report (default EPERM)
    std::int64_t value{0};   // allow/inject: the value the guest should see
    int injected_fd{-1};     // inject_fd: OUR descriptor, installed in the guest

    static Decision allow_it() { return {Kind::allow, 0, 0, -1}; }
    static Decision deny_it(int err = 1) { return {Kind::deny, err, 0, -1}; }
    static Decision give_fd(int fd) { return {Kind::inject_fd, 0, 0, fd}; }
};

// the supervisor's decision function. as far as the broker is concerned it is
// pure: scalars in, verdict out.
using Handler = std::function<Decision(const Request&)>;

// a listener on the guest's notification fd.
//
// move-only and closes on destruction, like every other capability-bearing type
// here. it owns no thread and no loop -- `poll_once` does one unit of work, so a
// caller (or a jaal source) drives it.
class Listener {
  public:
    Listener() = default;
    explicit Listener(OwnedFd fd) : fd_(std::move(fd)) {}

    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;
    Listener(Listener&&) noexcept = default;
    Listener& operator=(Listener&&) noexcept = default;

    bool valid() const { return fd_.valid(); }

    // the descriptor to wait on: readable exactly when a guest is blocked on a
    // brokered syscall, which is what an event loop wants.
    BorrowedFd fd() const { return fd_.borrow(); }

    // read one pending notification.
    Result<Request> next();

    // answer one. every request MUST be answered or the guest stays blocked
    // forever, which is a denial of service the supervisor inflicts on itself.
    Status respond(const Request& req, const Decision& d);

    // read one and answer it. the convenience path for a caller with no loop.
    Status poll_once(const Handler& h);

    // is the notification still live?
    //
    // MUST be checked immediately before acting on anything derived from guest
    // memory. a dead notification means the thread is gone and its id may have
    // been reused, so responding would answer a different syscall than the one
    // inspected. the kernel offers no other way to close that race.
    bool still_valid(const Request& req) const;

  private:
    OwnedFd fd_;
};

// ---------------------------------------------------------------------------
// a ready-made handler: enforce a NetAuthority over brokered socket calls.
// ---------------------------------------------------------------------------

// decide a brokered `socket()` from scalars alone -- domain, type, protocol are
// all registers, so this is sound with no memory access at all.
//
// the guest gets a socket only if the policy grants some network authority, and
// only for the families we are willing to broker.
Decision decide_socket(const Request& req, bool any_network_allowed);

}  // namespace clay::broker
