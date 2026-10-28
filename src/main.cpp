#include "ecc/crypto.hpp"
#include "ecc/point.hpp"

#include <iostream>
#include <string>

namespace {
ecc::crypto::Bytes to_bytes(const std::string& text) {
    return ecc::crypto::Bytes(text.begin(), text.end());
}

std::string to_string(const ecc::crypto::Bytes& bytes) {
    return std::string(bytes.begin(), bytes.end());
}
} // namespace

int main() {
    using ecc::educational::BigInt;
    using ecc::educational::Point;
    using namespace ecc::crypto;

    try {
        // Toy curve over F_17: y^2 = x^3 + 2x + 2, generator-like point (5, 1).
        const Point p(5, 1, 17, 2, 2);
        const Point twice_p = 2 * p;
        std::cout << "Educational point arithmetic over F_17\n"
                  << "P = (" << p.x() << ", " << p.y() << ")\n"
                  << "2P = (" << twice_p.x() << ", " << twice_p.y() << ")\n\n";

        const KeyPair recipient = KeyPair::generate();
        const Bytes plaintext = to_bytes("ECC demo: confidentiality plus integrity.");
        const EncryptedMessage encrypted = encrypt_for(recipient.public_key(), plaintext);
        const Bytes decrypted = decrypt_with(recipient, encrypted);

        const Bytes message = to_bytes("A message signed with ECDSA over P-256.");
        const Bytes signature = recipient.sign(message);
        const bool valid = verify_signature(recipient.public_key(), message, signature);

        std::cout << "OpenSSL P-256 ECDH + HKDF-SHA256 + AES-256-GCM\n"
                  << "Decrypted: " << to_string(decrypted) << "\n"
                  << "ECDSA-SHA256 signature verifies: " << std::boolalpha << valid << "\n"
                  << "Signature bytes (DER): " << signature.size() << "\n";
        return (decrypted == plaintext && valid) ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
