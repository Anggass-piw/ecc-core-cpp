#include "ecc/crypto.hpp"
#include "ecc/point.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

ecc::crypto::Bytes bytes(const std::string& text) {
    return ecc::crypto::Bytes(text.begin(), text.end());
}
} // namespace

int main() {
    try {
        using ecc::educational::Point;
        const Point p(5, 1, 17, 2, 2);
        const Point infinity = Point::infinity(17, 2, 2);
        require(p.is_on_curve(), "P must be on the curve");
        require(p + infinity == p, "identity point addition failed");
        require(p + (-p) == infinity, "inverse point addition failed");
        require(2 * p == p + p, "point doubling/operator overload failed");
        require(19 * p == infinity, "expected point order 19 over F_17");
        require((-1) * p == -p, "negative scalar multiplication failed");

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
