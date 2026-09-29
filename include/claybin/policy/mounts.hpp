// claybin: the mount model -- constructing a filesystem tree, bubblewrap-style.
//
// this is a DIFFERENT axis from FsAuthority, and claybin does both:
//
//   mounts    decide what is VISIBLE at all (a new root built from binds)
//   landlock  decide what is ACCESSIBLE among the things that are visible
//
// bubblewrap only has the first. a path that is bind-mounted read-write into a
// bwrap sandbox is fully writable, and the only way to narrow it is to not mount
// it. claybin can mount a tree and then further restrict it, so "mount
// /workspace rw but deny .git" is expressible without a second bind.
//
// the two also fail differently, which is the point of having both: a mount
// mistake makes a path invisible, a landlock mistake makes it inaccessible, and
// an attacker needs to beat both.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "claybin/core/lattice.hpp"
#include "claybin/policy/filesystem.hpp"

namespace clay {

enum class MountKind : std::uint8_t {
    bind,      // bind a host path in, read-write
    bind_ro,   // bind a host path in, read-only
    bind_dev,  // bind allowing device nodes (--dev-bind)
    tmpfs,     // fresh empty tmpfs
    proc,      // a new procfs, showing only this pid namespace
    devtmpfs,  // a minimal /dev: null, zero, full, random, urandom, tty
    mqueue,
    symlink,   // a symlink, not a mount, but part of tree construction
    dir,       // mkdir
};

constexpr const char* to_string(MountKind k) {
    switch (k) {
        case MountKind::bind: return "bind";
        case MountKind::bind_ro: return "bind-ro";
        case MountKind::bind_dev: return "dev-bind";
        case MountKind::tmpfs: return "tmpfs";
        case MountKind::proc: return "proc";
        case MountKind::devtmpfs: return "dev";
        case MountKind::mqueue: return "mqueue";
        case MountKind::symlink: return "symlink";
        case MountKind::dir: return "dir";
    }
    return "?";
}

struct Mount {
    MountKind kind{MountKind::bind_ro};
    std::string source;  // host path, or symlink target; empty for tmpfs/proc
    std::string dest;    // path inside the sandbox
    std::uint64_t size{0};      // tmpfs size limit, 0 = default
    std::uint32_t perms{0};     // octal mode for dir/symlink, 0 = default
    bool optional{false};       // --bind-try: skip if source is missing

    friend bool operator==(const Mount&, const Mount&) = default;
};

// an ordered list. unlike the other policy components this is NOT a lattice:
// mount order is semantically significant (you must create /usr before binding
// /usr/local under it), so it is a sequence, not a set.
//
// that means composition cannot be meet. two mount plans do not intersect in
// any meaningful way -- "the tree you get from both" is not well defined. so
// composing policies keeps the mounts of whichever side has them and rejects
// the combination if both do, rather than silently producing a tree neither
// caller asked for.
class MountPlan {
  public:
    MountPlan() = default;

    MountPlan& bind(std::string src, std::string dst) {
        mounts_.push_back({MountKind::bind, std::move(src), std::move(dst), 0, 0, false});
        return *this;
    }
    MountPlan& bind_ro(std::string src, std::string dst) {
        mounts_.push_back({MountKind::bind_ro, std::move(src), std::move(dst), 0, 0, false});
        return *this;
    }
    MountPlan& bind_try(std::string src, std::string dst, bool ro = true) {
        mounts_.push_back({ro ? MountKind::bind_ro : MountKind::bind, std::move(src),
                           std::move(dst), 0, 0, true});
        return *this;
    }
    MountPlan& dev_bind(std::string src, std::string dst) {
        mounts_.push_back({MountKind::bind_dev, std::move(src), std::move(dst), 0, 0, false});
        return *this;
    }
    MountPlan& tmpfs(std::string dst, std::uint64_t size = 0) {
        mounts_.push_back({MountKind::tmpfs, {}, std::move(dst), size, 0, false});
        return *this;
    }
    MountPlan& proc(std::string dst = "/proc") {
        mounts_.push_back({MountKind::proc, {}, std::move(dst), 0, 0, false});
        return *this;
    }
    MountPlan& dev(std::string dst = "/dev") {
        mounts_.push_back({MountKind::devtmpfs, {}, std::move(dst), 0, 0, false});
        return *this;
    }
    MountPlan& symlink(std::string target, std::string dst) {
        mounts_.push_back({MountKind::symlink, std::move(target), std::move(dst), 0, 0, false});
        return *this;
    }
    MountPlan& dir(std::string dst, std::uint32_t perms = 0755) {
        mounts_.push_back({MountKind::dir, {}, std::move(dst), 0, perms, false});
        return *this;
    }

    bool empty() const { return mounts_.empty(); }
    const std::vector<Mount>& mounts() const { return mounts_; }

    // derive the landlock grants implied by this tree, so a caller who only
    // described mounts still gets the second wall for free. read-only binds
    // become read grants, read-write binds become write grants.
    //
    // this is the bit that makes claybin strictly stronger than bwrap for the
    // same input: the same description drives both mechanisms.
    FsAuthority implied_authority() const {
        FsAuthority fs;
        for (const auto& m : mounts_) {
            switch (m.kind) {
                case MountKind::bind_ro:
                    fs.grant(m.dest, FileRights::exec());  // read + execute
                    break;
                case MountKind::bind:
                case MountKind::bind_dev:
                    fs.grant(m.dest, FileRights::all());
                    break;
                case MountKind::tmpfs:
                    fs.grant(m.dest, FileRights::write());
                    break;
                case MountKind::proc:
                case MountKind::devtmpfs:
                case MountKind::mqueue:
                    fs.grant(m.dest, FileRights::write());
                    break;
                case MountKind::symlink:
                case MountKind::dir:
                    break;  // not access grants on their own
            }
        }
        fs.normalize();
        return fs;
    }

    friend bool operator==(const MountPlan&, const MountPlan&) = default;

  private:
    std::vector<Mount> mounts_;
};

}  // namespace clay
