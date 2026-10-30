#include "ecc/crypto.hpp"
#include "ecc/point.hpp"
#include "openssl_size.hpp"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

ecc::crypto::Bytes bytes(const std::string& text) {
    return ecc::crypto::Bytes(text.begin(), text.end());
}

void test_size_guards() {
    using ecc::crypto::detail::checked_add_size;
    using ecc::crypto::detail::to_openssl_int_length;

    const auto int_max = static_cast<std::size_t>(std::numeric_limits<int>::max());
    require(to_openssl_int_length(int_max, "test length") == std::numeric_limits<int>::max(),
            "INT_MAX must be representable by OpenSSL length APIs");

    if constexpr (std::numeric_limits<std::size_t>::digits >
                  std::numeric_limits<int>::digits) {
        bool rejected_oversized_length = false;
        try {
            (void)to_openssl_int_length(int_max + 1, "test length");
        } catch (const std::length_error&) {
            rejected_oversized_length = true;
        }
        require(rejected_oversized_length, "length above INT_MAX must be rejected");
    }

    const auto size_max = std::numeric_limits<std::size_t>::max();
    require(checked_add_size(size_max - 1, 1, "test buffer") == size_max,
            "non-overflowing size addition must be preserved");
    bool rejected_overflow = false;
    try {
        (void)checked_add_size(size_max, 1, "test buffer");
    } catch (const std::length_error&) {
        rejected_overflow = true;
    }
    require(rejected_overflow, "size_t addition overflow must be rejected");
}
} // namespace

int main() {
    try {
        using ecc::educational::Point;
        test_size_guards();

        const Point p(5, 1, 17, 2, 2);
        const Point infinity = Point::infinity(17, 2, 2);
        require(p.is_on_curve(), "P must be on the curve");
        require(p + infinity == p, "identity point addition failed");
        require(p + (-p) == infinity, "inverse point addition failed");
        require(2 * p == p + p, "point doubling/operator overload failed");
        require(19 * p == infinity, "expected point order 19 over F_17");
        require((-1) * p == -p, "negative scalar multiplication failed");

        bool rejected_composite_modulus = false;
        try {
            (void)Point(0, 1, 15, 0, 1);
        } catch (const std::invalid_argument&) {
            rejected_composite_modulus = true;
        }
        require(rejected_composite_modulus, "composite field modulus must be rejected");

        const Point large_prime_field = Point::infinity(257, 0, 1);
        require(large_prime_field.is_infinity(), "known prime modulus above 227 must be accepted");
        bool rejected_large_composite_modulus = false;
        try {
            (void)Point::infinity(341, 0, 1);
        } catch (const std::invalid_argument&) {
            rejected_large_composite_modulus = true;
        }
        require(rejected_large_composite_modulus,
                "composite modulus above 227 must fail Miller-Rabin validation");

        bool rejected_singular_curve = false;
        try {
            (void)Point::infinity(17, 0, 0);
        } catch (const std::invalid_argument&) {
            rejected_singular_curve = true;
        }
        require(rejected_singular_curve, "singular curve parameters must be rejected");

        const auto recipient = ecc::crypto::KeyPair::generate();
        const auto plaintext = bytes("authenticated ECC encryption test");
        auto envelope = ecc::crypto::encrypt_for(recipient.public_key(), plaintext);
        require(ecc::crypto::decrypt_with(recipient, envelope) == plaintext,
                "ECDH/AES-GCM round trip failed");

        const auto signed_message = bytes("ECDSA test payload");
        const auto signature = recipient.sign(signed_message);
        require(ecc::crypto::verify_signature(recipient.public_key(), signed_message, signature),
                "ECDSA signature should verify");
        require(!ecc::crypto::verify_signature(recipient.public_key(), bytes("tampered"), signature),
                "ECDSA must reject a changed message");

        envelope.ciphertext.at(0) ^= 0x01;
        bool rejected = false;
        try {
            (void)ecc::crypto::decrypt_with(recipient, envelope);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        require(rejected, "AES-GCM must reject tampered ciphertext");

        std::cout << "All ECC core self-tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Self-test failed: " << error.what() << '\n';
        return 1;
    }
}
