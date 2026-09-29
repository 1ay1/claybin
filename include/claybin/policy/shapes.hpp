// claybin: ready-made sandbox shapes.
//
// these are the answer to "what does cross-platform actually buy me". each one
// is written so its mount plan is same-path only, which means its authority
// interpretation is EXACT (see Fidelity in mounts.hpp) and it compiles to a
// real sandbox on a host with no mount namespaces at all.
//
// a profile that needs remapping is marked, because it is linux-only by
// construction and the type system cannot tell you that -- only fidelity() can.
#pragma once

#include "claybin/policy/policy.hpp"
#include "claybin/policy/profiles.hpp"

namespace clay::shapes {

using namespace clay::literals;

// ---------------------------------------------------------------------------
// portable shapes: Fidelity::exact, so these work everywhere claybin has a
// backend, with the same meaning.
// ---------------------------------------------------------------------------

// read-only access to the system, nothing else. the base every other shape
// starts from: enough to run a dynamically linked binary and nothing more.
//
// same-path binds throughout, so an access-control-only backend expresses this
// exactly rather than approximately.
inline Policy<Draft> system_ro() {
    return Policy<Draft>{}
        .ro_bind("/usr", "/usr")
        // the loader. on a usr-merged distro these are symlinks into /usr, but
        // the loader opens them by these names, so they need grants of their
        // own. forgetting this is the single most common landlock mistake and
        // it surfaces as a baffling EACCES from execve.
        //
        // all optional, because which of them exist varies by distro: arch is
        // fully usr-merged and has no real /bin, some images have no /sbin at
        // all. a missing one is not a security failure -- the path simply is
        // not there, which is the safe direction.
        .bind_try("/lib", "/lib")
        .bind_try("/lib64", "/lib64")
        .bind_try("/bin", "/bin")
        .bind_try("/sbin", "/sbin")
        .bind_try("/etc/ld.so.cache", "/etc/ld.so.cache")
        .workdir("/");
}

// a build sandbox: the system read-only, one writable workspace, subprocesses
// allowed, no network.
//
// this is the shape a coding agent wants for "run the build and tell me what
// happened", and it is portable: the workspace keeps its own path.
inline Policy<Draft> builder(std::string workspace) {
    return system_ro()
        .bind(workspace, workspace)
        .workdir(std::move(workspace))
        .syscall_profile(profiles::compiler())
        .memory(4_GB)
        .processes(512);
}

// run one untrusted binary with no filesystem authority beyond the system and
// no subprocesses. the tightest useful shape.
inline Policy<Draft> strict() {
    return system_ro()
        .syscall_profile(profiles::base())
        .memory(512_MB)
        .processes(1);
}

// ---------------------------------------------------------------------------
// linux-only shapes: these remap paths or synthesize a tree, so
// fidelity() == impossible and compile() will refuse on a mountless host
// rather than pretend. that refusal is the feature.
// ---------------------------------------------------------------------------

// a flatpak-style container: the app sees a clean root with its data at a fixed
// location regardless of where it lives on the host.
//
// REMAPS, so linux-only by construction. that is exactly the capability a mount
// namespace has and access control does not.
inline Policy<Draft> app_container(std::string app_dir, std::string data_dir) {
    return Policy<Draft>{}
        .ro_bind("/usr", "/usr")
        .symlink("usr/lib", "/lib")
        .symlink("usr/lib", "/lib64")
        .symlink("usr/bin", "/bin")
        .ro_bind(std::move(app_dir), "/app")      // remap
        .bind(std::move(data_dir), "/home/user")  // remap
        .proc_fs("/proc")
        .dev_fs("/dev")
        .tmpfs("/tmp", 256_MB)
        .workdir("/home/user")
        .syscall_profile(profiles::compiler())
        .memory(2_GB)
        .processes(256);
}

}  // namespace clay::shapes
