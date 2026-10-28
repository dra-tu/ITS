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
    static constexpr size_t MAX_HASH_SIZE = std::max(SHA512_SIZE, ARGON2ID_SIZE);
    static constexpr size_t MAX_PASSWD_SIZE = 256;

    bool
    gen_salt(std::span<uint8_t, SALT_SIZE> out_salt);

    bool
    sha512(std::string_view text,
           std::span<uint8_t, SALT_SIZE> salt,
           std::span<uint8_t, SHA512_SIZE> out_hash);

    bool
    sha512(std::string_view text,
           std::span<uint8_t, SHA512_SIZE> out_hash);

    bool
    argon2id(std::string_view text,
             std::span<uint8_t, SALT_SIZE> salt,
             std::span<uint8_t, ARGON2ID_SIZE> out_hash);

}
