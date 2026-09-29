// the security argument of this library is "composition can only restrict".
// that argument is exactly the meet-semilattice laws, so they get property
// tests, not comments. if a type here goes red, there is a privilege bug.

#include "harness.hpp"

#include "claybin/policy/filesystem.hpp"
#include "claybin/policy/policy.hpp"
#include "claybin/policy/resources.hpp"
#include "claybin/policy/syscalls.hpp"

using namespace clay;
using namespace clay::test;

// checks every law for one sample triple.
template <Lattice T>
void check_laws(const char* what, const T& a, const T& b, const T& c) {
#define LAW(expr)                                                                    \
    do {                                                                             \
        if (!(expr)) std::fprintf(stderr, "  [%s] law broken: %s\n", what, #expr);   \
        ::clay::test::report((expr), #expr, __FILE__, __LINE__);                     \
    } while (0)
    LAW((a & a) == a);                        // idempotent
    LAW((a & b) == (b & a));                  // commutative
    LAW(((a & b) & c) == (a & (b & c)));      // associative
    LAW(a.subsumes(a & b));                   // decreasing (left)
    LAW(b.subsumes(a & b));                   // decreasing (right)
    LAW((a & T::nothing()) == T::nothing());  // bottom absorbs
    LAW((a & T::everything()) == a);          // top is identity
    // the order must agree with the meet, else `subsumes` is lying
    LAW(a.subsumes(b) == ((a & b) == b));
#undef LAW
}

template <Lattice T, class Gen>
void fuzz_laws(const char* what, Gen gen, int iters = 400) {
    Rng rng{0xC1AB1Full};
    for (int i = 0; i < iters; ++i) check_laws<T>(what, gen(rng), gen(rng), gen(rng));
}

int main() {
    // -- FileRights --------------------------------------------------------
    auto rights = [](Rng& r) { return FileRights{static_cast<std::uint32_t>(r.next()) & 0x1fffu}; };
    fuzz_laws<FileRights>("FileRights", rights);

    // -- Bytes / Count / Nanos (min-lattices) ------------------------------
    fuzz_laws<Bytes>("Bytes", [](Rng& r) {
        return r.coin(10) ? Bytes::unlimited() : Bytes{r.next() % 4096};
    });

    // -- FsAuthority: the interesting one ----------------------------------
    static const char* kPaths[] = {"/",          "/usr",     "/usr/lib", "/usr/bin",
                                   "/workspace", "/workspace/build", "/tmp", "/home",
                                   "/home/ayush", "/etc"};
    auto gen_fs = [](Rng& r) {
        FsAuthority fs;
        std::uint32_t n = r.below(5);
        for (std::uint32_t i = 0; i < n; ++i) {
            const char* p = kPaths[r.below(10)];
            fs.restrict_to(p, FileRights{static_cast<std::uint32_t>(r.next()) & 0x1fffu});
        }
        fs.normalize();
        return fs;
    };
    fuzz_laws<FsAuthority>("FsAuthority", gen_fs, 300);

    // meet must be EXACT pointwise, not an approximation. check at every named
    // path, including ones neither side mentions.
    {
        Rng r{0x5EEDull};
        for (int i = 0; i < 300; ++i) {
            FsAuthority a = gen_fs(r), b = gen_fs(r);
            FsAuthority m = a & b;
            for (const char* p : kPaths)
                CHECK_EQ(m.effective(p), a.effective(p).meet(b.effective(p)));
        }
    }

    // normalize() must not change meaning, only size.
    {
        Rng r{0xABCDull};
        for (int i = 0; i < 200; ++i) {
            FsAuthority a = gen_fs(r);
            FsAuthority n = a;
            n.normalize();
            for (const char* p : kPaths) CHECK_EQ(n.effective(p), a.effective(p));
        }
    }

    // -- SyscallPolicy -----------------------------------------------------
    auto gen_sys = [](Rng& r) {
        SyscallPolicy p;
        p.set_default(static_cast<SysAction>(r.below(7)));
        std::uint32_t n = r.below(8);
        for (std::uint32_t i = 0; i < n; ++i)
            p.set(r.below(64), static_cast<SysAction>(r.below(7)));
        return p;
    };
    fuzz_laws<SyscallPolicy>("SyscallPolicy", gen_sys, 300);

    // and pointwise exactness for syscall actions too
    {
        Rng r{0xF00Dull};
        for (int i = 0; i < 300; ++i) {
            SyscallPolicy a = gen_sys(r), b = gen_sys(r);
            SyscallPolicy m = a & b;
            for (SysNr nr = 0; nr < 64; ++nr)
                CHECK(m.action_for(nr) == meet(a.action_for(nr), b.action_for(nr)));
        }
    }

    // -- NetAuthority ------------------------------------------------------
    auto gen_net = [](Rng& r) {
        NetAuthority n;
        if (r.coin(30)) n.allow_any(NetOps{static_cast<std::uint32_t>(r.next()) & 0x1fu});
        std::uint32_t k = r.below(4);
        for (std::uint32_t i = 0; i < k; ++i) {
            const char* hosts[] = {"", "a.com", "b.com"};
            n.allow(hosts[r.below(3)], static_cast<std::uint16_t>(r.below(3) * 443),
                    NetOps{static_cast<std::uint32_t>(r.next()) & 0x1fu});
        }
        return n;
    };
    fuzz_laws<NetAuthority>("NetAuthority", gen_net, 300);

    // -- ResourceLimits ----------------------------------------------------
    fuzz_laws<ResourceLimits>("ResourceLimits", [](Rng& r) {
        ResourceLimits l;
        l.memory = Bytes{r.next() % 1000};
        l.pids = Count{r.next() % 1000};
        l.cpu_time = Nanos{r.next() % 1000};
        l.wall_clock = Nanos{r.next() % 1000};
        l.memory_swap = Bytes{r.next() % 1000};
        l.open_files = Count{r.next() % 1000};
        l.cpu_weight = Count{r.next() % 1000};
        l.io_read_bps = Bytes{r.next() % 1000};
        l.io_write_bps = Bytes{r.next() % 1000};
        l.core_size = Bytes{r.next() % 1000};
        return l;
    });

    // -- the headline property ---------------------------------------------
    // composing any two policies never yields authority neither side had.
    {
        Rng r{0x1234ull};
        for (int i = 0; i < 200; ++i) {
            auto a = Policy<Draft>{}
                         .read(kPaths[r.below(10)])
                         .memory(Bytes{r.next() % 4096})
                         .processes(r.next() % 256)
                         .seal();
            auto b = Policy<Draft>{}
                         .read_write(kPaths[r.below(10)])
                         .memory(Bytes{r.next() % 4096})
                         .processes(r.next() % 256)
                         .seal();
            auto m = a & b;
            CHECK(a.subsumes(m));
            CHECK(b.subsumes(m));
            for (const char* p : kPaths) {
                FileRights got = m.data().fs.effective(p);
                CHECK(a.data().fs.effective(p).subsumes(got));
                CHECK(b.data().fs.effective(p).subsumes(got));
            }
        }
    }

    return finish("lattice_laws_test");
}
