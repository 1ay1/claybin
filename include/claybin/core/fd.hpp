// claybin: file descriptors as capabilities.
//
// an fd is the purest capability in unix. it is unforgeable (you cannot make one
// up), unambiguous (it names an object, not a path that might be re-pointed
// under you), and immune to every symlink and TOCTOU race that path resolution
// suffers from. bubblewrap uses that: `--bind-fd N DEST` binds `/proc/self/fd/N`
// rather than a path, and the kernel resolves it to the exact object the caller
// held.
//
// so fds get a type here rather than being passed around as `int`.
//
// the awkward part is that an fd is BORROWED by default: the caller owns it, and
// closing it or letting it leak into the guest are both bugs. so this file makes
// ownership explicit in the type, and makes the default the safe one.
#pragma once

#include <cstdint>
#include <string>
#include <utility>

#include "claybin/core/error.hpp"

namespace clay {

// a descriptor the CALLER owns and we merely read. copying one is fine, because
// copying does not transfer the duty to close.
//
// this is what a `--bind-fd` argument is: the caller keeps the fd, we look at
// what it points to while building the sandbox, and we must not close it.
class BorrowedFd {
  public:
    constexpr BorrowedFd() = default;
    constexpr explicit BorrowedFd(int fd) : fd_(fd) {}

    constexpr int get() const { return fd_; }
    constexpr bool valid() const { return fd_ >= 0; }

    friend constexpr bool operator==(BorrowedFd, BorrowedFd) = default;

  private:
    int fd_{-1};
};

// a descriptor WE own and must close. move-only, closes in the destructor, so a
// plan that is built and then abandoned cannot leak one into the next sandbox.
//
// this is affine in the same sense as the rest of claybin's typestate: you get
// exactly one chance to use it, and the type will not let you use it twice.
class OwnedFd {
  public:
    OwnedFd() = default;
    explicit OwnedFd(int fd) : fd_(fd) {}

    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;

    OwnedFd(OwnedFd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    OwnedFd& operator=(OwnedFd&& o) noexcept {
        if (this != &o) {
            reset();
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }

    ~OwnedFd() { reset(); }

    int get() const { return fd_; }
    bool valid() const { return fd_ >= 0; }

    // hand the descriptor to someone else, giving up the duty to close it.
    [[nodiscard]] int release() {
        int f = fd_;
        fd_ = -1;
        return f;
    }

    // borrow it without transferring ownership.
    BorrowedFd borrow() const { return BorrowedFd{fd_}; }

    void reset();

  private:
    int fd_{-1};
};

// content to place inside the sandbox, read from a descriptor the caller holds.
//
// `--file N DEST` and `--bind-data N DEST` both mean "read this fd and make its
// contents appear at DEST". the difference is only in how it is made to appear:
// a plain file on a tmpfs, or a bind mount of a file we immediately unlink so no
// other path can reach it.
struct FdContent {
    BorrowedFd source{};
    std::string dest{};
    std::uint32_t perms{0644};

    // bind the content in rather than writing a plain file. the bind version is
    // strictly stronger: the backing file is unlinked straight after the mount,
    // so even a guest that somehow escapes the tree cannot open it by path.
    bool as_bind{false};
    bool read_only{false};

    friend bool operator==(const FdContent&, const FdContent&) = default;
};

// resolve a descriptor to the path it currently names, or "" on failure.
//
// this exists because the kernel will NOT bind-mount through /proc/self/fd/N:
// mount() on a magic symlink returns EINVAL regardless of how the fd was
// opened. so `--bind-fd` has to become a path bind, and the only honest place
// to do the conversion is in the parent, before any namespace work, where the
// caller's own view of the filesystem still applies.
std::string resolve_fd(BorrowedFd fd);

}  // namespace clay
