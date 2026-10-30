#include "ecc/point.hpp"

#include <boost/multiprecision/miller_rabin.hpp>

#include <random>
#include <stdexcept>
#include <utility>

namespace ecc::educational {
namespace {

bool is_probable_prime(const BigInt& candidate) {
    if (candidate < 2) return false;
    if (candidate <= 227) {
        return boost::multiprecision::miller_rabin_test(candidate, 0);
    }

    std::random_device source;
    std::seed_seq seed{source(), source(), source(), source(),
                       source(), source(), source(), source()};
    std::mt19937_64 generator(seed);
    return boost::multiprecision::miller_rabin_test(candidate, 32, generator);
}

} // namespace

Point::Point(BigInt x, BigInt y, BigInt p, BigInt a, BigInt b)
    : Point(std::move(x), std::move(y), std::move(p), std::move(a),
            std::move(b), false) {
    if (p_ <= 3) {
        throw std::invalid_argument("field modulus p must be greater than 3");
    }
    if (!is_probable_prime(p_)) {
        throw std::invalid_argument("field modulus p must be prime");
    }
    x_ = mod(x_, p_);
    y_ = mod(y_, p_);
    if (mod(4 * a_ * a_ * a_ + 27 * b_ * b_, p_) == 0) {
        throw std::invalid_argument("curve must be nonsingular over the field");
    }
    if (!is_on_curve()) {
        throw std::invalid_argument("point is not on the supplied curve");
    }
}

Point::Point(BigInt x, BigInt y, BigInt p, BigInt a, BigInt b, bool infinity)
    : x_(std::move(x)), y_(std::move(y)), p_(std::move(p)),
      a_(mod(std::move(a), p_)), b_(mod(std::move(b), p_)),
      infinity_(infinity) {}

Point Point::infinity(BigInt p, BigInt a, BigInt b) {
    if (p <= 3) {
        throw std::invalid_argument("field modulus p must be greater than 3");
    }
    if (!is_probable_prime(p)) {
        throw std::invalid_argument("field modulus p must be prime");
    }
    if (mod(4 * a * a * a + 27 * b * b, p) == 0) {
        throw std::invalid_argument("curve must be nonsingular over the field");
    }
    return Point(0, 0, std::move(p), std::move(a), std::move(b), true);
}

BigInt Point::mod(BigInt value, const BigInt& modulus) {
    if (modulus <= 0) {
        throw std::invalid_argument("field modulus p must be positive");
    }
    value %= modulus;
    if (value < 0) value += modulus;
    return value;
}

BigInt Point::inverse(const BigInt& value, const BigInt& modulus) {
    // Fermat's little theorem: this assumes modulus is prime.
    const BigInt normalized = mod(value, modulus);
    if (normalized == 0) {
        throw std::domain_error("zero has no inverse in the field");
    }
    const BigInt result = boost::multiprecision::powm(normalized, modulus - 2, modulus);
    if (mod(normalized * result, modulus) != 1) {
        throw std::domain_error("modular inverse failed; modulus may not be prime");
    }
    return result;
}

bool Point::is_on_curve() const {
    if (infinity_) return true;
    const BigInt lhs = mod(y_ * y_, p_);
    const BigInt rhs = mod(x_ * x_ * x_ + a_ * x_ + b_, p_);
    return lhs == rhs;
}

void Point::ensure_same_curve(const Point& rhs) const {
    if (p_ != rhs.p_ || a_ != rhs.a_ || b_ != rhs.b_) {
        throw std::invalid_argument("cannot combine points from different curves");
    }
}

Point Point::operator+(const Point& rhs) const {
    ensure_same_curve(rhs);
    if (infinity_) return rhs;
    if (rhs.infinity_) return *this;

    BigInt slope;
    if (x_ == rhs.x_ && mod(y_ + rhs.y_, p_) == 0) {
        return Point(0, 0, p_, a_, b_, true);
    }

    if (x_ == rhs.x_ && y_ == rhs.y_) {
        if (mod(2 * y_, p_) == 0) return Point(0, 0, p_, a_, b_, true);
        slope = mod((3 * x_ * x_ + a_) * inverse(2 * y_, p_), p_);
    } else {
        slope = mod((rhs.y_ - y_) * inverse(rhs.x_ - x_, p_), p_);
    }

    const BigInt x3 = mod(slope * slope - x_ - rhs.x_, p_);
    const BigInt y3 = mod(slope * (x_ - x3) - y_, p_);
    return Point(x3, y3, p_, a_, b_, false);
}

Point Point::operator-() const {
    if (infinity_) return *this;
    return Point(x_, mod(-y_, p_), p_, a_, b_, false);
}

Point Point::operator*(BigInt scalar) const {
    if (scalar == 0 || infinity_) return Point(0, 0, p_, a_, b_, true);
    if (scalar < 0) return (-*this) * (-scalar);

    // Straightforward double-and-add for clarity, not constant-time.
    Point result = infinity(p_, a_, b_);
    Point addend = *this;
    while (scalar > 0) {
        if ((scalar & 1) != 0) result = result + addend;
        addend = addend + addend;
        scalar >>= 1;
    }
    return result;
}

bool operator==(const Point& lhs, const Point& rhs) {
    if (lhs.p_ != rhs.p_ || lhs.a_ != rhs.a_ || lhs.b_ != rhs.b_) return false;
    if (lhs.infinity_ || rhs.infinity_) return lhs.infinity_ == rhs.infinity_;
    return lhs.x_ == rhs.x_ && lhs.y_ == rhs.y_;
}

} // namespace ecc::educational
