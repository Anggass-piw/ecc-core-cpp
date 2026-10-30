#include "ecc/crypto.hpp"
#include "openssl_size.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <array>
#include <memory>
#include <stdexcept>
#include <string>

namespace ecc::crypto {
namespace {

constexpr char kCurveName[] = "prime256v1";
constexpr std::size_t kAesKeyBytes = 32;
constexpr std::size_t kNonceBytes = 12;
constexpr std::size_t kSaltBytes = 16;
constexpr std::size_t kTagBytes = 16;
constexpr char kHkdfInfo[] = "ecc-core-cpp/ecdh-aes-256-gcm/v1";

using PkeyPtr = std::shared_ptr<EVP_PKEY>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

[[noreturn]] void fail(const char* action) {
    const unsigned long code = ERR_get_error();
    if (code == 0) throw std::runtime_error(action);
    char buffer[256]{};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    throw std::runtime_error(std::string(action) + ": " + buffer);
}

PkeyPtr own(EVP_PKEY* key) {
    if (!key) fail("OpenSSL key operation failed");
    return PkeyPtr(key, EVP_PKEY_free);
}

PkeyPtr generate_ec_key() {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) fail("EC keygen init failed");

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                         const_cast<char*>(kCurveName), 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0) fail("setting EC curve failed");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_generate(ctx.get(), &raw) <= 0) fail("EC key generation failed");
    return own(raw);
}

PkeyPtr import_public_key(const Bytes& encoded) {
    if (encoded.empty()) throw std::invalid_argument("public key must not be empty");
    char curve_name[] = "prime256v1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                          const_cast<std::uint8_t*>(encoded.data()), encoded.size()),
        OSSL_PARAM_construct_end()
    };

    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0) fail("public key import init failed");
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        fail("public key import failed");
    }
    PkeyPtr key = own(raw);
    PkeyCtxPtr check(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    if (!check || EVP_PKEY_public_check(check.get()) <= 0) {
        throw std::invalid_argument("invalid EC public key");
    }
    return key;
}

Bytes export_public_key(EVP_PKEY* key) {
    std::size_t length = 0;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                        nullptr, 0, &length) <= 0 || length == 0) {
        fail("public key size query failed");
    }
    Bytes output(length);
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                        output.data(), output.size(), &length) <= 0) {
        fail("public key export failed");
    }
    output.resize(length);
    return output;
}

Bytes derive_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(private_key, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key) <= 0) {
        fail("ECDH derive init failed");
    }
    std::size_t length = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &length) <= 0) fail("ECDH size query failed");
    Bytes secret(length);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &length) <= 0) fail("ECDH derive failed");
    secret.resize(length);
    return secret;
}

Bytes derive_aes_key(const Bytes& shared_secret, const Bytes& salt) {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(),
            detail::to_openssl_int_length(salt.size(), "HKDF salt")) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), shared_secret.data(),
            detail::to_openssl_int_length(shared_secret.size(), "ECDH shared secret")) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(),
            reinterpret_cast<const unsigned char*>(kHkdfInfo),
            detail::to_openssl_int_length(sizeof(kHkdfInfo) - 1, "HKDF info")) <= 0) {
        fail("HKDF setup failed");
    }
    Bytes key(kAesKeyBytes);
    std::size_t length = key.size();
    if (EVP_PKEY_derive(ctx.get(), key.data(), &length) <= 0 || length != key.size()) {
        fail("HKDF key derivation failed");
    }
    return key;
}

void add_aad(EVP_CIPHER_CTX* ctx, const EncryptedMessage& message, bool encrypting) {
    int out_length = 0;
    auto update = [&](const Bytes& bytes) {
        if (!bytes.empty()) {
            const int ok = encrypting
                ? EVP_EncryptUpdate(ctx, nullptr, &out_length, bytes.data(),
                    detail::to_openssl_int_length(bytes.size(), "AES-GCM AAD"))
                : EVP_DecryptUpdate(ctx, nullptr, &out_length, bytes.data(),
                    detail::to_openssl_int_length(bytes.size(), "AES-GCM AAD"));
            if (ok <= 0) fail("AES-GCM AAD processing failed");
        }
    };
    update(message.ephemeral_public_key);
    update(message.hkdf_salt);
}

Bytes aes_gcm_encrypt(const Bytes& key, EncryptedMessage& message, const Bytes& plaintext) {
    const int nonce_length = detail::to_openssl_int_length(message.nonce.size(), "AES-GCM nonce");
    const int plaintext_length = detail::to_openssl_int_length(plaintext.size(), "AES-GCM plaintext");
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            nonce_length, nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), message.nonce.data()) <= 0) {
        fail("AES-GCM encryption init failed");
    }
    add_aad(ctx.get(), message, true);

    Bytes ciphertext(detail::checked_add_size(plaintext.size(), 16,
                                               "AES-GCM ciphertext buffer"));
    int produced = 0;
    if (!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &produced,
                                                plaintext.data(), plaintext_length) <= 0) {
        fail("AES-GCM encryption failed");
    }
    if (produced < 0 || static_cast<std::size_t>(produced) > ciphertext.size()) {
        fail("AES-GCM returned an invalid update length");
    }
    int final_bytes = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + produced, &final_bytes) <= 0) {
        fail("AES-GCM finalization failed");
    }
    if (produced < 0 || final_bytes < 0) fail("AES-GCM returned an invalid output length");
    const std::size_t ciphertext_length = detail::checked_add_size(
        static_cast<std::size_t>(produced), static_cast<std::size_t>(final_bytes),
        "AES-GCM ciphertext output");
    if (ciphertext_length > ciphertext.size()) fail("AES-GCM returned an oversized output");
    ciphertext.resize(ciphertext_length);
    message.tag.resize(kTagBytes);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
            detail::to_openssl_int_length(message.tag.size(), "AES-GCM tag"),
            message.tag.data()) <= 0) {
        fail("AES-GCM tag retrieval failed");
    }
    return ciphertext;
}

Bytes aes_gcm_decrypt(const Bytes& key, const EncryptedMessage& message) {
    if (message.nonce.size() != kNonceBytes || message.tag.size() != kTagBytes ||
        message.hkdf_salt.size() != kSaltBytes) {
        throw std::invalid_argument("invalid encrypted message parameters");
    }
    const int nonce_length = detail::to_openssl_int_length(message.nonce.size(), "AES-GCM nonce");
    const int ciphertext_input_length = detail::to_openssl_int_length(
        message.ciphertext.size(), "AES-GCM ciphertext");
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            nonce_length, nullptr) <= 0 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), message.nonce.data()) <= 0) {
        fail("AES-GCM decryption init failed");
    }
    add_aad(ctx.get(), message, false);

    Bytes plaintext(detail::checked_add_size(message.ciphertext.size(), 16,
                                              "AES-GCM plaintext buffer"));
    int produced = 0;
    if (!message.ciphertext.empty() && EVP_DecryptUpdate(ctx.get(), plaintext.data(), &produced,
                    message.ciphertext.data(), ciphertext_input_length) <= 0) {
        fail("AES-GCM decryption failed");
    }
    if (produced < 0 || static_cast<std::size_t>(produced) > plaintext.size()) {
        fail("AES-GCM returned an invalid update length");
    }
    Bytes tag = message.tag;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
            detail::to_openssl_int_length(tag.size(), "AES-GCM tag"), tag.data()) <= 0) {
        fail("AES-GCM tag setup failed");
    }
    int final_bytes = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + produced, &final_bytes) <= 0) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error("AES-GCM authentication failed: message was altered or key is wrong");
    }
    if (produced < 0 || final_bytes < 0) fail("AES-GCM returned an invalid output length");
    const std::size_t plaintext_length = detail::checked_add_size(
        static_cast<std::size_t>(produced), static_cast<std::size_t>(final_bytes),
        "AES-GCM plaintext output");
    if (plaintext_length > plaintext.size()) fail("AES-GCM returned an oversized output");
    plaintext.resize(plaintext_length);
    return plaintext;
}

} // namespace

KeyPair::KeyPair(std::shared_ptr<EVP_PKEY> key) : key_(std::move(key)) {}

KeyPair KeyPair::generate() {
    return KeyPair(generate_ec_key());
}

Bytes KeyPair::public_key() const {
    return export_public_key(key_.get());
}

EVP_PKEY* KeyPair::native_handle() const noexcept {
    return key_.get();
}

Bytes KeyPair::sign(const Bytes& message) const {
    MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key_.get()) <= 0 ||
        EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) <= 0) {
        fail("ECDSA signing init/update failed");
    }
    std::size_t length = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &length) <= 0) fail("ECDSA signature size query failed");
    Bytes signature(length);
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &length) <= 0) fail("ECDSA signing failed");
    signature.resize(length);
    return signature;
}

bool verify_signature(const Bytes& public_key, const Bytes& message, const Bytes& signature) {
    PkeyPtr key = import_public_key(public_key);
    MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) <= 0 ||
        EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) <= 0) {
        fail("ECDSA verification init/update failed");
    }
    const int result = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
    if (result == 1) return true;
    if (result == 0) {
        ERR_clear_error();
        return false;
    }
    fail("ECDSA verification failed");
}

EncryptedMessage encrypt_for(const Bytes& recipient_public_key, const Bytes& plaintext) {
    PkeyPtr ephemeral = generate_ec_key();
    PkeyPtr recipient = import_public_key(recipient_public_key);
    const Bytes secret = derive_shared_secret(ephemeral.get(), recipient.get());

    EncryptedMessage message;
    message.ephemeral_public_key = export_public_key(ephemeral.get());
    message.hkdf_salt.resize(kSaltBytes);
    message.nonce.resize(kNonceBytes);
    if (RAND_bytes(message.hkdf_salt.data(), detail::to_openssl_int_length(
                    message.hkdf_salt.size(), "HKDF salt")) != 1 ||
        RAND_bytes(message.nonce.data(), detail::to_openssl_int_length(
                    message.nonce.size(), "AES-GCM nonce")) != 1) {
        fail("secure random generation failed");
    }
    const Bytes key = derive_aes_key(secret, message.hkdf_salt);
    message.ciphertext = aes_gcm_encrypt(key, message, plaintext);
    return message;
}

Bytes decrypt_with(const KeyPair& recipient, const EncryptedMessage& message) {
    PkeyPtr ephemeral = import_public_key(message.ephemeral_public_key);
    const Bytes secret = derive_shared_secret(recipient.native_handle(), ephemeral.get());
    const Bytes key = derive_aes_key(secret, message.hkdf_salt);
    return aes_gcm_decrypt(key, message);
}

} // namespace ecc::crypto
