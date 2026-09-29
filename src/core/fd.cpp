#include "claybin/core/fd.hpp"

#include <cstdio>

#if defined(__linux__)
#include <unistd.h>
#endif

namespace clay {

void OwnedFd::reset() {
    if (fd_ < 0) return;
#if defined(__linux__)
    // no error check: a failing close on an fd we are discarding tells us
    // nothing actionable, and retrying it is the classic double-close bug.
    ::close(fd_);
#endif
    fd_ = -1;
}

std::string resolve_fd(BorrowedFd fd) {
#if defined(__linux__)
    if (!fd.valid()) return {};
    char link[64];
    std::snprintf(link, sizeof link, "/proc/self/fd/%d", fd.get());
    char target[4096];
    ssize_t n = ::readlink(link, target, sizeof target - 1);
    if (n <= 0) return {};
    target[n] = '\0';
    // readlink on a magic symlink can yield a non-path for sockets and pipes,
    // spelled like "socket:[12345]". those name no filesystem object, so there
    // is nothing to bind and pretending otherwise would be worse than failing.
    if (target[0] != '/') return {};
    // the kernel appends " (deleted)" when the target has been unlinked. binding
    // that path would bind whatever now lives there instead -- a real hazard, so
    // refuse rather than guess.
    std::string s{target, static_cast<std::size_t>(n)};
    if (s.size() > 10 && s.compare(s.size() - 10, 10, " (deleted)") == 0) return {};
    return s;
#else
    (void)fd;
    return {};
#endif
}

}  // namespace clay
