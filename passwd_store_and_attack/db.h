#pragma once

#include <sqlite3.h>

#include "hashing.h"

namespace db {

    const constexpr char *DEFAULT_DB_FILE = "login.db";

    class Login {
    public:
        char    email[hashing::EMAIL_SIZE];
        uint8_t salt[hashing::SALT_SIZE];
        uint8_t sha512_NoSalt[hashing::SHA512_SIZE];
        uint8_t sha512_Salt[hashing::SHA512_SIZE];
        uint8_t argon2id[hashing::ARGON2ID_SIZE];

        bool
        operator==(const Login &other) const;

        bool
        create(const std::string_view &usr_email,
               const std::string_view &passwd,
               const std::span<uint8_t, hashing::SALT_SIZE> &usr_salt);

        bool
        create(const std::string_view &usr_email,
               const std::string_view &passwd);

        void
        pretty_print(std::ostream& os);
    };

    class DB {
    public:
        void *connection = nullptr;

        bool connect(const std::string_view &filename = DEFAULT_DB_FILE);
        void disconnect();

        static bool
        copy_column_value(sqlite3_stmt *stmt, int iCol, std::span<uint8_t> dest);

        bool save_login(const Login &login) const;
        bool load_login(const std::string_view &user_email, Login &out_login) const;
    };

}
