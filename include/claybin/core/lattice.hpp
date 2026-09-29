// claybin: authority lattice.
//
// every policy component is a bounded meet-semilattice. composition is meet,
// so composing policies can only ever remove authority. this file defines the
// concept; the laws it implies are checked in tests/lattice_laws_test.cpp.
#pragma once

#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>

namespace clay {

// ---------------------------------------------------------------------------
// concept
// ---------------------------------------------------------------------------

// a bounded meet-semilattice over authority.
//
//   bottom  = nothing()     no authority
//   top     = everything()  all authority this type can express
//   meet    = greatest lower bound
//   subsumes= the induced partial order (a >= b)
//
// laws (tested):
//   a & a == a                          idempotent
//   a & b == b & a                      commutative
//   (a & b) & c == a & (b & c)          associative
//   a & b <= a,  a & b <= b             decreasing
//   a.subsumes(b) <=> (a & b) == b      order agrees with meet
//   a & nothing() == nothing()          bottom absorbs
//   a & everything() == a               top is identity
template <class T>
concept Lattice = std::equality_comparable<T> && std::copyable<T> && requires(const T a, const T b) {
    { T::nothing() } -> std::same_as<T>;
    { T::everything() } -> std::same_as<T>;
    { a.meet(b) } -> std::same_as<T>;
    { a.subsumes(b) } -> std::same_as<bool>;
    { a.is_nothing() } -> std::same_as<bool>;
};

// the only composition operator we expose. there is deliberately no operator|:
// a public join would let a caller widen a sealed policy, and the entire
// security argument of this library is that they cannot.
template <Lattice T>
constexpr T operator&(const T& a, const T& b) {
    return a.meet(b);
}

template <Lattice T>
constexpr T& operator&=(T& a, const T& b) {
    a = a.meet(b);
    return a;
}

// ---------------------------------------------------------------------------
// bitset lattice: the common case, where authority is a set of flags and meet
// is intersection.
// ---------------------------------------------------------------------------

// crtp-free reusable flag lattice. `Tag` distinguishes otherwise identical
// instantiations so you cannot meet a FileRights with a NetRights.
template <class Tag, std::unsigned_integral Rep = std::uint64_t>
class Flags {
  public:
    using rep_type = Rep;

    constexpr Flags() = default;
    constexpr explicit Flags(Rep bits) : bits_(bits) {}

    static constexpr Flags nothing() { return Flags{Rep{0}}; }
    static constexpr Flags everything() { return Flags{static_cast<Rep>(~Rep{0})}; }

    constexpr Flags meet(Flags o) const { return Flags{static_cast<Rep>(bits_ & o.bits_)}; }

    // NOT public api as an operator. used internally by builders, where adding
    // authority is explicit user intent on a Draft.
    constexpr Flags unsafe_join(Flags o) const { return Flags{static_cast<Rep>(bits_ | o.bits_)}; }
    constexpr Flags without(Flags o) const {
        return Flags{static_cast<Rep>(bits_ & static_cast<Rep>(~o.bits_))};
    }

    constexpr bool subsumes(Flags o) const { return (bits_ & o.bits_) == o.bits_; }
    constexpr bool is_nothing() const { return bits_ == Rep{0}; }
    constexpr bool any(Flags o) const { return (bits_ & o.bits_) != Rep{0}; }

    constexpr Rep bits() const { return bits_; }
    constexpr explicit operator bool() const { return bits_ != Rep{0}; }

    friend constexpr bool operator==(Flags, Flags) = default;
    friend constexpr auto operator<=>(Flags, Flags) = default;

  private:
    Rep bits_{};
};

// ---------------------------------------------------------------------------
// numeric limit lattice: authority is "you may use up to N", so meet is min and
// bottom is 0. `unlimited` is top.
// ---------------------------------------------------------------------------

template <class Tag, class Rep = std::uint64_t>
class Limit {
  public:
    using rep_type = Rep;

    constexpr Limit() : value_(kUnlimited) {}
    constexpr explicit Limit(Rep v) : value_(v) {}

    static constexpr Rep kUnlimited = static_cast<Rep>(~Rep{0});

    static constexpr Limit nothing() { return Limit{Rep{0}}; }
    static constexpr Limit everything() { return Limit{kUnlimited}; }
    static constexpr Limit unlimited() { return Limit{kUnlimited}; }

    // tighter of the two wins. a limit is a ceiling, so meet is min.
    constexpr Limit meet(Limit o) const { return Limit{value_ < o.value_ ? value_ : o.value_}; }

    // a >= b means a permits at least as much as b.
    constexpr bool subsumes(Limit o) const { return value_ >= o.value_; }
    constexpr bool is_nothing() const { return value_ == Rep{0}; }
    constexpr bool is_unlimited() const { return value_ == kUnlimited; }

    constexpr Rep value() const { return value_; }

    friend constexpr bool operator==(Limit, Limit) = default;

  private:
    Rep value_;
};

// ---------------------------------------------------------------------------
// tri-state enforcement. never a bool: "did the backend enforce this" has more
// than two useful answers, and collapsing them is how libraries lie.
// ---------------------------------------------------------------------------

enum class Enforcement : std::uint8_t {
    none = 0,      // not enforced at all. the backend says so out loud.
    advisory = 1,  // observed and reported, not blocked.
    partial = 2,   // blocked on the common paths, known gaps.
    strong = 3,    // enforced by the kernel for this process tree.
    isolated = 4,  // enforced by a separate kernel / vm boundary.
};

// a report is only as strong as its weakest mechanism, so combining two
// enforcement claims takes the min. same meet-semilattice shape as everything
// else here.
constexpr Enforcement meet(Enforcement a, Enforcement b) { return a < b ? a : b; }

constexpr const char* to_string(Enforcement e) {
    switch (e) {
        case Enforcement::none: return "none";
        case Enforcement::advisory: return "advisory";
        case Enforcement::partial: return "partial";
        case Enforcement::strong: return "strong";
        case Enforcement::isolated: return "isolated";
    }
    return "?";
}

}  // namespace clay
