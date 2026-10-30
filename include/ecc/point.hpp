#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <utility>

namespace ecc::educational {

using BigInt = boost::multiprecision::cpp_int;

// Affine point on y^2 = x^3 + ax + b (mod p).
// This implementation is for learning only: cpp_int and the algorithms used
// here are variable-time and must not be used with secret scalars.
// p must be prime; construction applies a Miller-Rabin probable-prime check (up to 32 rounds).
class Point {
public:
    Point(BigInt x, BigInt y, BigInt p, BigInt a, BigInt b);

    static Point infinity(BigInt p, BigInt a, BigInt b);

    bool is_infinity() const noexcept { return infinity_; }
    bool is_on_curve() const;
    const BigInt& x() const noexcept { return x_; }
    const BigInt& y() const noexcept { return y_; }
    const BigInt& field_modulus() const noexcept { return p_; }

    Point operator+(const Point& rhs) const;
    Point operator-() const;
    Point operator*(BigInt scalar) const;

    friend Point operator*(BigInt scalar, const Point& point) {
        return point * std::move(scalar);
    }
    friend bool operator==(const Point& lhs, const Point& rhs);
    friend bool operator!=(const Point& lhs, const Point& rhs) {
        return !(lhs == rhs);
    }

private:
    Point(BigInt x, BigInt y, BigInt p, BigInt a, BigInt b, bool infinity);
    static BigInt mod(BigInt value, const BigInt& modulus);
    static BigInt inverse(const BigInt& value, const BigInt& modulus);
    void ensure_same_curve(const Point& rhs) const;

    BigInt x_;
    BigInt y_;
    BigInt p_;
    BigInt a_;
    BigInt b_;
    bool infinity_;
};

} // namespace ecc::educational
