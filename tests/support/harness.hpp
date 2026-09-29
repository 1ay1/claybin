// minimal test harness. no gtest, no catch2 -- the library has zero deps and so
// do its tests.
#pragma once

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string_view>

namespace clay::test {

inline int g_failures = 0;
inline int g_checks = 0;

inline void report(bool ok, std::string_view expr, const char* file, int line) {
    ++g_checks;
    if (ok) return;
    ++g_failures;
    std::fprintf(stderr, "FAIL %s:%d: %.*s\n", file, line, static_cast<int>(expr.size()),
                 expr.data());
}

inline int finish(const char* name) {
    if (g_failures == 0) {
        std::fprintf(stderr, "ok %s (%d checks)\n", name, g_checks);
        return 0;
    }
    std::fprintf(stderr, "FAILED %s: %d/%d checks failed\n", name, g_failures, g_checks);
    return 1;
}

// deterministic prng: property tests must reproduce exactly on failure.
class Rng {
  public:
    explicit Rng(std::uint64_t seed = 0x9e3779b97f4a7c15ull) : s_(seed | 1) {}
    std::uint64_t next() {
        s_ ^= s_ << 13;
        s_ ^= s_ >> 7;
        s_ ^= s_ << 17;
        return s_;
    }
    std::uint32_t below(std::uint32_t n) { return n ? static_cast<std::uint32_t>(next() % n) : 0; }
    bool coin(std::uint32_t pct = 50) { return below(100) < pct; }

  private:
    std::uint64_t s_;
};

}  // namespace clay::test

#define CHECK(expr) ::clay::test::report((expr), #expr, __FILE__, __LINE__)
#define CHECK_EQ(a, b) ::clay::test::report((a) == (b), #a " == " #b, __FILE__, __LINE__)
