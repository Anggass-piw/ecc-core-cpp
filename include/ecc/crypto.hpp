#pragma once

#include <cstdint>
#include <memory>
#include <vector>

typedef struct evp_pkey_st EVP_PKEY;

namespace ecc::crypto {

using Bytes = std::vector<std::uint8_t>;

class KeyPair {
public:
    static KeyPair generate();

    Bytes public_key() const;
    Bytes sign(const Bytes& message) const;
    EVP_PKEY* native_handle() const noexcept;

private:
    explicit KeyPair(std::shared_ptr<EVP_PKEY> key);
    std::shared_ptr<EVP_PKEY> key_;
};

bool verify_signature(const Bytes& public_key,
                      const Bytes& message,
                      const Bytes& signature);

// ECDH + HKDF-SHA256 + AES-256-GCM envelope. This is a compact example
// composition, not a standardized or independently audited protocol.
struct EncryptedMessage {
    Bytes ephemeral_public_key;
    Bytes hkdf_salt;
    Bytes nonce;
    Bytes ciphertext;
    Bytes tag;
};

EncryptedMessage encrypt_for(const Bytes& recipient_public_key,
                             const Bytes& plaintext);
Bytes decrypt_with(const KeyPair& recipient, const EncryptedMessage& message);

} // namespace ecc::crypto
