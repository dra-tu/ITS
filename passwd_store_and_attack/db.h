#pragma once

#include <sqlite3.h>

#include "hashing.h"

namespace db {

    const constexpr char *DEFAULT_DB_FILE = "login.db";

    // BEGINN TOTP-ERGAENZUNG
    //  Groessen der neuen Datenbankfelder
    const constexpr size_t TOTP_SECRET_SIZE = 20; // TOTP-Secret: 160 Bit
    const constexpr size_t TOTP_NONCE_SIZE  = 12; // AES-GCM-Nonce: 12 Byte
    const constexpr size_t TOTP_TAG_SIZE    = 16; // AES-GCM-Tag: 16 Byte
    // ENDE TOTP-ERGAENZUNG

    class Login {
    public:
        char    email[hashing::EMAIL_SIZE];
        uint8_t salt[hashing::SALT_SIZE];
        uint8_t sha512_NoSalt[hashing::SHA512_SIZE];
        uint8_t sha512_Salt[hashing::SHA512_SIZE];
        uint8_t argon2id[hashing::ARGON2ID_SIZE];
        // BEGINN TOTP-ERGAENZUNG
        //  Felder totp_secret_enc, totp_nonce und totp_tag beim Benutzerkonto
        uint8_t totp_secret_enc[TOTP_SECRET_SIZE];
        uint8_t totp_nonce[TOTP_NONCE_SIZE];
        uint8_t totp_tag[TOTP_TAG_SIZE];
        // ENDE TOTP-ERGAENZUNG

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

        bool update_login(const Login &login) const;
        bool save_login(const Login &login) const;
        bool load_login(const std::string_view &user_email, Login &out_login) const;
        // BEGINN TOTP-ERGAENZUNG
        // Datenbankfunktionen zum Speichern und Laden der TOTP-Felder
        bool save_totp(const Login &login, bool ersetzen) const;
        bool load_totp(const std::string_view &user_email, Login &out_login) const;
        // Replay-Schutz: Zeitabschnitt eines TOTP-Codes als verbraucht markieren
        bool use_totp_step(const std::string_view &user_email, int64_t step) const;
        // ENDE TOTP-ERGAENZUNG

        void attack();

    private:
        template<class HASH_FUNC>
        void attack_base(const std::string &tag, std::string sql, bool check_salt, std::span<uint8_t> hash_buf,
                         HASH_FUNC hash_func);
        void attack_sha512();
        void attack_sha512_salt();
        void attack_argon2id();
    };
}
