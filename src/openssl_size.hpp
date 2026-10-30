#pragma once

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>

namespace ecc::crypto::detail {

inline int to_openssl_int_length(std::size_t length, const char* description) {
    if constexpr (std::numeric_limits<std::size_t>::digits >
                  std::numeric_limits<int>::digits) {
        if (length > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
            throw std::length_error(std::string(description) +
                                    " exceeds OpenSSL's INT_MAX length limit");
        }
    }
    return static_cast<int>(length);
}

inline std::size_t checked_add_size(std::size_t left, std::size_t right,
                                    const char* description) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::length_error(std::string(description) + " size overflows size_t");
    }
    return left + right;
}

} // namespace ecc::crypto::detail
