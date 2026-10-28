#include "db.h"

#include <ostream>
#include <iomanip>
#include <iostream>
#include <cstring>

#include <sqlite3.h>

namespace db {

    bool
    Login::operator==(const Login &other) const {
        if (0 != memcmp(email,         other.email,         hashing::EMAIL_SIZE)) return false;
        if (0 != memcmp(salt,          other.salt,          hashing::SALT_SIZE)) return false;
        if (0 != memcmp(sha512_NoSalt, other.sha512_NoSalt, hashing::SHA512_SIZE)) return false;
        if (0 != memcmp(sha512_Salt,   other.sha512_Salt,   hashing::SHA512_SIZE)) return false;
        if (0 != memcmp(argon2id,      other.argon2id,      hashing::ARGON2ID_SIZE)) return false;

        return true;
    }

    bool
    Login::create(const std::string_view &usr_email,
           const std::string_view &passwd,
           const std::span<uint8_t, hashing::SALT_SIZE> &usr_salt) {
        usr_email.copy(email, hashing::EMAIL_SIZE);
        memcpy(salt, usr_salt.data(), hashing::SALT_SIZE);

        std::span sha512(sha512_NoSalt);
        const std::span salt_span(salt);
        std::span sha512_salt_span(sha512_Salt);
        std::span argon2id_span(argon2id);

        if (!hashing::sha512(passwd, sha512)) return false;
        if (!hashing::sha512(passwd, salt_span, sha512_salt_span)) return false;
        if (!hashing::argon2id(passwd, salt_span, argon2id_span)) return false;

        return true;
    }

    bool
    Login::create(const std::string_view &usr_email,
                  const std::string_view &passwd)
    {
        usr_email.copy(this->email, hashing::EMAIL_SIZE);

        std::span sha512_span(sha512_NoSalt);
        const std::span salt_span(salt);
        std::span sha512_salt_span(sha512_Salt);
        std::span argon2id_span(argon2id);

        if (!hashing::sha512(passwd, sha512_span)) return false;
        if (!hashing::gen_salt(salt_span)) return false;
        if (!hashing::sha512(passwd, salt_span, sha512_salt_span)) return false;
        if (!hashing::argon2id(passwd, salt_span, argon2id_span)) return false;

        return true;
    }

    void
    Login::pretty_print(std::ostream& os) {
        os << email << " {\n";
        os << std::hex << std::uppercase << std::setfill('0');
        os << "\tsalt:        [";
        for (const uint8_t byte : salt) os << std::setw(2) << (int)byte;
        os << "]\n";
        os << "\tsha512:      [";
        for (const uint8_t byte : sha512_NoSalt) os << std::setw(2) << (int)byte;
        os << "]\n";
        os << "\tsha512_Salt: [";
        for (const uint8_t byte : sha512_Salt) os << std::setw(2) << (int)byte;
        os << "]\n";
        os << "\targon2id:    [";
        for (const uint8_t byte : argon2id) os << std::setw(2) << (int)byte;
        os << "]\n";
        os << std::dec << "}" << std::endl;
    }


    bool
    DB::connect(const std::string_view &filename) {
        sqlite3 *db = nullptr;
        if (sqlite3_open(filename.data(), &db) != SQLITE_OK) {
            std::cout << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return false;
        }
        connection = db;
        return true;
    }

    void
    DB::disconnect() {
        sqlite3_close((sqlite3*) connection);
        connection = nullptr;
    }

    bool
    DB::save_login(const Login &login) const {
        static std::string_view sql_create =
            "INSERT INTO login (email, salt, sha512_salt, sha512_NoSalt, argon2id)"
            " VALUES           (:EMAIL, :SALT, :SHA512_SALT, :SHA512_NO_SALT, :ARGON2ID)";

        if (!connection) return false;
        sqlite3 *db = (sqlite3*) connection;

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(db, sql_create.data(), (int) sql_create.size(),
                           &stmt, nullptr);
        if (res) {
            std::cout << sqlite3_errmsg(db) << "\n";
            return false;
        }

        // thes functions can techecly fail but it is very unlickly (out of memory or missuse)
        const int email_idx       = sqlite3_bind_parameter_index(stmt, ":EMAIL");
        const int sha512_idx      = sqlite3_bind_parameter_index(stmt, ":SHA512_NO_SALT");
        const int salt_idx        = sqlite3_bind_parameter_index(stmt, ":SALT");
        const int sha512_salt_idx = sqlite3_bind_parameter_index(stmt, ":SHA512_SALT");
        const int argon2id_idx    = sqlite3_bind_parameter_index(stmt, ":ARGON2ID");
        sqlite3_bind_text(stmt, email_idx,       login.email,                       -1,                     SQLITE_STATIC);
        sqlite3_bind_text(stmt, sha512_idx,      (const char*) login.sha512_NoSalt, hashing::SHA512_SIZE,   SQLITE_STATIC);
        sqlite3_bind_text(stmt, salt_idx,        (const char*) login.salt,          hashing::SALT_SIZE,     SQLITE_STATIC);
        sqlite3_bind_text(stmt, sha512_salt_idx, (const char*) login.sha512_Salt,   hashing::SHA512_SIZE,   SQLITE_STATIC);
        sqlite3_bind_text(stmt, argon2id_idx,    (const char*) login.argon2id,      hashing::ARGON2ID_SIZE, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) std::cerr << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt);

        return true;
    }

    bool
    DB::copy_column_value(sqlite3_stmt *stmt, const int iCol, std::span<uint8_t> dest) {
        const void *db_val    = sqlite3_column_blob(stmt,  iCol);
        const size_t db_val_size = (size_t)sqlite3_column_bytes(stmt, iCol);
        if (db_val_size != dest.size()) return false;
        memcpy(dest.data(), db_val, dest.size());
        return true;
    }

    bool
    DB::load_login(const std::string_view &user_email, Login &out_login) const {
        // space befor "WHERE is needed"
        static std::string_view sql_query =
            "SELECT salt, sha512_salt, sha512_NoSalt, argon2id FROM login"
            " WHERE email = :EMAIL";

        if (!connection) return false;
        sqlite3 *db = (sqlite3*) connection;

        user_email.copy(out_login.email, hashing::EMAIL_SIZE);

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(db, sql_query.data(), (int) sql_query.size(), &stmt, nullptr);
        if (res) {
            std::cout << sqlite3_errmsg(db) << "\n";
            return false;
        }

        const int email_idx  = sqlite3_bind_parameter_index(stmt, ":EMAIL");
        sqlite3_bind_text(stmt, email_idx, out_login.email, -1, SQLITE_STATIC);

        bool found_one = false;
        while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
            found_one = true;
            copy_column_value(stmt, 0, out_login.salt);
            copy_column_value(stmt, 1, out_login.sha512_Salt);
            copy_column_value(stmt, 2, out_login.sha512_NoSalt);
            copy_column_value(stmt, 3, out_login.argon2id);
        }
        if (res != SQLITE_DONE) std::cerr << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt);
        return found_one;
    }
}
