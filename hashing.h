#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace hashing {

    static constexpr size_t SHA512_SIZE   = 64;
    static constexpr size_t ARGON2ID_SIZE = 32;
    static constexpr size_t SALT_SIZE     = 16;
    static constexpr size_t EMAIL_SIZE    = 254;

    bool
    gen_salt(const std::span<uint8_t, SALT_SIZE> &out_salt);

    bool
    sha512(const std::string_view &text,
           const std::span<uint8_t> &salt,
           std::span<uint8_t, SHA512_SIZE> &out_hash);

    bool
    sha512(const std::string_view &text,
           std::span<uint8_t,
           SHA512_SIZE> &out_hash);

    bool
    argon2id(const std::string_view &text,
             const std::span<uint8_t, SALT_SIZE> &salt,
             std::span<uint8_t, ARGON2ID_SIZE> &out_hash);

}
