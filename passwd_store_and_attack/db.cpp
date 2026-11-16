#include "db.h"

#include <ostream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <chrono>
using Clock = std::chrono::steady_clock;

#include "rainbow.h"

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
        if (sqlite3_open_v2(filename.data(), &db, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
            std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;
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
    DB::copy_column_value(sqlite3_stmt *stmt, const int iCol, std::span<uint8_t> dest) {
        const void *db_val    = sqlite3_column_blob(stmt,  iCol);
        const size_t db_val_size = (size_t)sqlite3_column_bytes(stmt, iCol);
        if (db_val_size != dest.size()) return false;
        memcpy(dest.data(), db_val, dest.size());
        return true;
    }

    bool
    DB::update_login(const Login &login) const {
        const std::string sql_update =
            "UPDATE login"
            " SET salt = :SALT, sha512_salt = :SHA512_SALT, sha512_NoSalt = :SHA512_NO_SALT , argon2id = :ARGON2ID"
            " WHERE email = :EMAIL";

        if (!connection) return false;
        sqlite3 *db = (sqlite3*) connection;

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(db, sql_update.data(), (int) sql_update.size(), &stmt, nullptr);
        if (res) {
            std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

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

        if (sqlite3_step(stmt) != SQLITE_DONE) std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;;
        sqlite3_finalize(stmt);

        return true;
    }

    bool
    DB::save_login(const Login &login) const {
        static std::string_view sql_create =
            "INSERT INTO login (email, salt, sha512_salt, sha512_NoSalt, argon2id)"
            " VALUES           (:EMAIL, :SALT, :SHA512_SALT, :SHA512_NO_SALT, :ARGON2ID)";

        if (!connection) return false;
        sqlite3 *db = (sqlite3*) connection;

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(db, sql_create.data(), (int) sql_create.size(), &stmt, nullptr);
        if (res) {
            std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;
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

        if (sqlite3_step(stmt) != SQLITE_DONE) std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;;
        sqlite3_finalize(stmt);

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
            std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;
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
        if (res != SQLITE_DONE) std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;;
        sqlite3_finalize(stmt);
        return found_one;
    }

    bool DB::load_totp_secret(const std::string_view &email,
                          std::string &out_secret) const {
    if (!connection || email.empty()) {
        return false;
    }

    sqlite3 *db = static_cast<sqlite3*>(connection);
    const char *sql =
        "SELECT totp_secret FROM login WHERE email = ?1";

    sqlite3_stmt *stmt = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(
        stmt, 1, email.data(),
        static_cast<int>(email.size()), SQLITE_TRANSIENT
    );

    bool found = false;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *value = sqlite3_column_text(stmt, 0);

        if (value != nullptr) {
            out_secret = reinterpret_cast<const char*>(value);
            found = true;
        }
    }

    sqlite3_finalize(stmt);
    return found;
}

    bool
    DB::start_recovery(const std::string_view &email,
                       const std::span<const uint8_t> &token_hash,
                       int64_t expires_at) const {
        if (!connection || email.empty() ||
            email.size() >= hashing::EMAIL_SIZE || token_hash.empty()) {
            return false;
        }

        sqlite3 *db = (sqlite3*) connection;

        static constexpr std::string_view sql_query =
            "INSERT OR REPLACE INTO recovery (email, token_hash, expires_at) "
            "VALUES (:EMAIL, :TOKEN_HASH, :EXPIRES_AT)";

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(
            db, sql_query.data(), (int)sql_query.size(), &stmt, nullptr);

        if (res != SQLITE_OK) {
            std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":EMAIL"),
                          email.data(), (int)email.size(), SQLITE_TRANSIENT);

        sqlite3_bind_blob(stmt, sqlite3_bind_parameter_index(stmt, ":TOKEN_HASH"),
                          token_hash.data(), (int)token_hash.size(), SQLITE_TRANSIENT);

        sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":EXPIRES_AT"),
                           expires_at);

        res = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return res == SQLITE_DONE;
    }


    bool
    DB::load_recovery(const std::string_view &email,
                      std::span<uint8_t> token_hash,
                      int64_t &expires_at) const {
        if (!connection || email.empty() || !token_hash.data()) {
            return false;
        }

        sqlite3 *db = (sqlite3*) connection;

        static constexpr std::string_view sql_query =
            "SELECT token_hash, expires_at FROM recovery WHERE email = :EMAIL";

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(
            db, sql_query.data(), (int)sql_query.size(), &stmt, nullptr);

        if (res != SQLITE_OK) {
            std::cerr << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":EMAIL"),
                          email.data(), (int)email.size(), SQLITE_TRANSIENT);

        bool found = false;

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const void *blob = sqlite3_column_blob(stmt, 0);
            int blob_size = sqlite3_column_bytes(stmt, 0);

            if (blob && blob_size == (int)token_hash.size()) {
                std::memcpy(token_hash.data(), blob, token_hash.size());
                expires_at = sqlite3_column_int64(stmt, 1);
                found = true;
            }
        }

        sqlite3_finalize(stmt);
        return found;
    }


    bool
    DB::finish_recovery(const Login &login,
                        const std::string_view &totp_secret) const {
        if (!connection || !totp_secret.data() || totp_secret.empty()) {
            return false;
        }

        sqlite3 *db = (sqlite3*) connection;

        if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK) {
            return false;
        }

        static constexpr std::string_view update_query =
            "UPDATE login SET salt = :SALT, sha512_salt = :SHA512_SALT, "
            "sha512_NoSalt = :SHA512_NOSALT, argon2id = :ARGON2ID, "
            "totp_secret = :TOTP_SECRET WHERE email = :EMAIL";

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(
            db, update_query.data(), (int)update_query.size(), &stmt, nullptr);

        if (res != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }

        sqlite3_bind_blob(stmt, sqlite3_bind_parameter_index(stmt, ":SALT"),
                          login.salt, hashing::SALT_SIZE, SQLITE_TRANSIENT);

        sqlite3_bind_blob(stmt, sqlite3_bind_parameter_index(stmt, ":SHA512_SALT"),
                          login.sha512_Salt, hashing::SHA512_SIZE, SQLITE_TRANSIENT);

        sqlite3_bind_blob(stmt, sqlite3_bind_parameter_index(stmt, ":SHA512_NOSALT"),
                          login.sha512_NoSalt, hashing::SHA512_SIZE, SQLITE_TRANSIENT);

        sqlite3_bind_blob(stmt, sqlite3_bind_parameter_index(stmt, ":ARGON2ID"),
                          login.argon2id, hashing::ARGON2ID_SIZE, SQLITE_TRANSIENT);

        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":TOTP_SECRET"),
                          totp_secret.data(), (int)totp_secret.size(), SQLITE_TRANSIENT);

        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":EMAIL"),
                          login.email, -1, SQLITE_TRANSIENT);

        res = sqlite3_step(stmt);
        bool updated = (res == SQLITE_DONE && sqlite3_changes(db) == 1);
        sqlite3_finalize(stmt);

        if (!updated) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }

        static constexpr std::string_view delete_query =
            "DELETE FROM recovery WHERE email = :EMAIL";

        stmt = nullptr;
        res = sqlite3_prepare_v2(
            db, delete_query.data(), (int)delete_query.size(), &stmt, nullptr);

        if (res != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }

        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":EMAIL"),
                          login.email, -1, SQLITE_TRANSIENT);

        res = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (res != SQLITE_DONE ||
            sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }

        return true;
    }


    static bool
    check_row(std::string_view email, std::span<uint8_t> hash, size_t hash_expected_size,
              std::span<uint8_t> salt = std::span<uint8_t>{},
              bool check_salt = false) {
        if (!email.data() || !hash.data() || (check_salt && !salt.data())) {
            std::cerr << "[WARNING] salt or sha512_Salt or email field is missing" << std::endl;
            return false;
        }
        if (email.size() >= hashing::EMAIL_SIZE) {
            std::cerr << "[WARNING] email: " << email << " is to long" << std::endl;
            return false;
        }
        if (hash.size() != hash_expected_size) {
            std::cerr << "[WARNING] hash for " << email << " has wrong size" << std::endl;
            return false;
        }
        if (check_salt && (salt.size() != hashing::SALT_SIZE)) {
            std::cerr << "[WARNING] salt for " << email << " has wrong size" << std::endl;
            return false;
        }
        return true;
    }

    template<typename HASH_FUNC>
    void DB::attack_base(const std::string& tag, std::string sql, bool check_salt,
                         std::span<uint8_t> hash_buf, HASH_FUNC hash_func) {
        if (!connection) {
            std::cerr << "[ERROR] call to DB::attack without connection" << std::endl;
            return;
        }
        sqlite3 *db = (sqlite3*) connection;

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(db, sql.data(), (int)sql.size(), &stmt, nullptr);
        if (res) {
            std::cerr << "[ERROR] " << sqlite3_errmsg(db) << std::endl;
            return;
        }

        size_t found   = 0;
        size_t total   = 0;
        size_t skipped = 0;
        const Clock::time_point time_start = Clock::now();
        while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
            if (sqlite3_column_count(stmt) != (check_salt ? 3 : 2)) {
                std::cerr << "[WARNING] unexpected column count" << std::endl;
                skipped++;
                continue;
            }

            std::string_view email{(char*) sqlite3_column_blob(stmt, 0), (size_t) sqlite3_column_bytes(stmt, 0)};
            std::span hash{(uint8_t*) sqlite3_column_blob(stmt, 1), (size_t) sqlite3_column_bytes(stmt, 1)};
            std::span<uint8_t> salt;
            if (check_salt)
                salt = std::span{(uint8_t*) sqlite3_column_blob(stmt, 2), (size_t) sqlite3_column_bytes(stmt, 2)};
            total++;

            if (!check_row(email, hash, hash_buf.size(), salt, check_salt)) {
                skipped++;
                continue;
            }

            const Clock::time_point time_start_pw = Clock::now();
            for (size_t i = 0; i < rainbow::passwd.size(); ++i) {
                const std::string_view passwd = rainbow::passwd[i];
                hash_func(i, passwd, salt, hash_buf);

                if (memcmp(hash_buf.data(), hash.data(), hash_buf.size()) == 0) {
                    const Clock::time_point time_end_pw = Clock::now();
                    long diff_µs  = std::chrono::duration_cast<std::chrono::microseconds>(time_end_pw - time_start_pw).count();
                    double diff_s = (double)diff_µs / 1000000.0;

                    std::printf("%lfs | %ldµs | login \"%s\" \"%s\"\n", diff_s, diff_µs, email.data(), passwd.data());
                    found++;
                    break;
                }
            }
        }
        if (res != SQLITE_DONE) {
            std::cerr << "[ERROR] fror sqlite3 " << sqlite3_errmsg(db) << std::endl;
        }
        const Clock::time_point time_end = Clock::now();
        sqlite3_finalize(stmt);

        long diff_µs  = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start).count();
        double diff_s = (double)diff_µs / 1000000.0;
        std::printf("%s> %3ld/%3ld (skipped: %ld)\n", tag.data(), found, total, skipped);
        std::cout << tag << "> " << diff_s << "s | " << diff_µs << "µs\n";
        std::cout << std::endl;
    }

    void
    DB::attack_sha512() {
        std::array<uint8_t, hashing::SHA512_SIZE> hash_buf{};

        attack_base("sha512", "SELECT email, sha512_NoSalt FROM login", false, hash_buf,
        [](size_t &i, const std::string_view &pw, std::span<uint8_t> &salt, std::span<uint8_t> &hash_buf) {
            (void) pw; (void) salt;
            memcpy(hash_buf.data(), rainbow::sha512[i].data(), hashing::SHA512_SIZE);
        });
    }

    void
    DB::attack_sha512_salt() {
        std::array<uint8_t, hashing::SHA512_SIZE> hash_buf{};

        attack_base("sha512-salt", "SELECT email, sha512_salt, salt FROM login", true, hash_buf,
        [](size_t &i, const std::string_view &pw, std::span<uint8_t> &salt, std::span<uint8_t> &hash_buf) {
            (void) i;
            std::span<uint8_t, hashing::SHA512_SIZE> cal_hash(hash_buf.data(), hashing::SHA512_SIZE);
            std::span<uint8_t, hashing::SALT_SIZE> salt_span(salt.data(), hashing::SALT_SIZE);
            hashing::sha512(pw, salt_span, cal_hash);
        });
    }

    void
    DB::attack_argon2id() {
        std::array<uint8_t, hashing::ARGON2ID_SIZE> hash_buf{};

        attack_base("argon2id", "SELECT email, argon2id, salt FROM login", true, hash_buf,
        [](size_t &i, const std::string_view &pw, std::span<uint8_t> &salt, std::span<uint8_t> &hash_buf) {
            (void) i;
            std::span<uint8_t, hashing::ARGON2ID_SIZE> cal_hash(hash_buf.data(), hashing::ARGON2ID_SIZE);
            std::span<uint8_t, hashing::SALT_SIZE> salt_span(salt.data(), hashing::SALT_SIZE);
            hashing::argon2id(pw, salt_span, cal_hash);
        });
    }

    void
    DB::attack() {
        if (!connection) {
            std::cerr << "[ERROR] call to DB::attack without connection" << std::endl;
            return;
        }

        rainbow::fill_sha512();
        attack_sha512();
        attack_sha512_salt();
        attack_argon2id();
    }
}
