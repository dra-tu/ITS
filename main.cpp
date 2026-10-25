#include <iostream>
#include <cstring>
#include <array>
#include <span>

#include <iomanip>

#include <sqlite3.h>

// evp stuff for hash
#include <openssl/evp.h>

// specific hash functino
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "hashing.h"

/* hash sha256 example (duck.ai)
 * unsigned char hash[SHA256_DIGEST_LENGTH];
 * SHA256(reinterpret_cast<unsigned char*>(const_cast<char*>(str)),
 *        std::strlen(str),
 *        hash);
 **/

#define SQL_LOGIN_T "login"

class Login {
public:
    char email[hashing::EMAIL_SIZE];
    uint8_t salt[hashing::SALT_SIZE];
    uint8_t sha512_NoSalt[hashing::SHA512_SIZE];
    uint8_t sha512_Salt[hashing::SHA512_SIZE];
    uint8_t argon2id[hashing::ARGON2ID_SIZE];

    void prity_print(std::ostream& os) {
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

    void create(const char *email, std::string_view &passwd) {
        // this->email = email;
        strncpy(this->email, email, hashing::EMAIL_SIZE);

        std::span sha512(sha512_NoSalt);
        hashing::sha512(passwd, sha512);

        if (1 != RAND_bytes(salt, hashing::SALT_SIZE)) {
            std::cerr << ERR_get_error() << std::endl;
            return;
        }
        const std::span salt_span(salt);

        std::span sha512_salt(sha512_Salt);
        hashing::sha512(passwd, salt_span, sha512_salt);

        std::span argon2id_span(argon2id);
        hashing::argon2id(passwd, salt_span, argon2id_span);
    }

    void load(sqlite3 *db, const char *email) {
        static std::string_view sql_query = "SELECT * FROM " SQL_LOGIN_T " WHERE email = :EMAIL";

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(db, sql_query.data(), sql_query.size(),
                           &stmt, nullptr);
        if (res) {
            std::cout << sqlite3_errmsg(db) << "\n";
            return;
        }

        int email_idx  = sqlite3_bind_parameter_index(stmt, ":EMAIL");
        sqlite3_bind_text(stmt, email_idx, email, -1, SQLITE_STATIC);

        while (SQLITE_ROW == (res = sqlite3_step(stmt))) {
            std::cout << "found row\n";
            const char *email_db = (char*) sqlite3_column_text(stmt, 0);
            const int email_db_size = sqlite3_column_bytes(stmt, 0);
			if (email_db_size <= hashing::EMAIL_SIZE)
            	memcpy(this->email, email_db, email_db_size);

            const void *salt_db = sqlite3_column_blob(stmt, 1);
            const int salt_db_size = sqlite3_column_bytes(stmt, 1);
			if (salt_db_size == hashing::SALT_SIZE)
            	memcpy(this->salt, salt_db, hashing::SALT_SIZE);

            const void *sha512_salt_db = sqlite3_column_blob(stmt, 2);
            const int sha512_salt_db_size = sqlite3_column_bytes(stmt, 2);
            if (sha512_salt_db_size == hashing::SHA512_SIZE)
                memcpy(this->sha512_Salt, sha512_salt_db, hashing::SHA512_SIZE);

            const void *sha512_db = sqlite3_column_blob(stmt, 3);
            const int sha512_db_size = sqlite3_column_bytes(stmt, 3);
            if (sha512_db_size == hashing::SHA512_SIZE)
                memcpy(this->sha512_NoSalt, sha512_db, hashing::SHA512_SIZE);

            const void *argon2id_db = sqlite3_column_blob(stmt, 4);
            const int argon2id_db_size = sqlite3_column_bytes(stmt, 4);
            if (argon2id_db_size == hashing::ARGON2ID_SIZE)
                memcpy(this->argon2id, argon2id_db, hashing::ARGON2ID_SIZE);
        }
        if (res != SQLITE_DONE) std::cerr << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt);
    }

    void save(sqlite3 *db) {
        static std::string_view sql_create =
            "INSERT INTO " SQL_LOGIN_T " "
            "VALUES (:EMAIL, :SALT, :SHA512_SALT, :SHA512_NO_SALT, :ARGON2ID)";

        sqlite3_stmt *stmt = nullptr;
        int res = sqlite3_prepare_v2(db, sql_create.data(), sql_create.size(),
                           &stmt, nullptr);
        if (res) {
            std::cout << sqlite3_errmsg(db) << "\n";
            return;
        }

        int email_idx  = sqlite3_bind_parameter_index(stmt, ":EMAIL");
        sqlite3_bind_text(stmt, email_idx, email, -1, SQLITE_STATIC);

        int sha512_idx = sqlite3_bind_parameter_index(stmt, ":SHA512_NO_SALT");
        sqlite3_bind_text(stmt, sha512_idx, (const char*) sha512_NoSalt, hashing::SHA512_SIZE, SQLITE_STATIC);

        int salt_idx = sqlite3_bind_parameter_index(stmt, ":SALT");
        sqlite3_bind_text(stmt, salt_idx, (const char*) salt, hashing::SALT_SIZE, SQLITE_STATIC);

        int sha512_salt_idx = sqlite3_bind_parameter_index(stmt, ":SHA512_SALT");
        sqlite3_bind_text(stmt, sha512_salt_idx , (const char*) sha512_Salt, hashing::SHA512_SIZE, SQLITE_STATIC);

        int argon2id_idx = sqlite3_bind_parameter_index(stmt, ":ARGON2ID");
        sqlite3_bind_text(stmt, argon2id_idx , (const char*) argon2id, hashing::ARGON2ID_SIZE, SQLITE_STATIC);

        res = sqlite3_step(stmt);
        if (res != SQLITE_DONE) std::cerr << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt);
    }
};

namespace db {
    static constexpr char FILE_LOGIN[] = "assets/login.db";

    static const char *SQL_CREATE_T =
        "CREATE TABLE " SQL_LOGIN_T " ("
            "email  VARCHAR(254) PRIMARY KEY,"
            "salt   BLOB(16)"
            "sha512 BLOB(64)"
        ");";

    static sqlite3 *f(const char *filename) {
        sqlite3 *db = nullptr;

        if (SQLITE_OK != sqlite3_open(filename, &db)) {
            std::cout << "[ERROR][SQLITE3] " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return nullptr;
        }

        return db;
    }
}

int get(std::span<char*> args) {
    if (args.size() != 1) {
        std::cerr << "[ERROR] new args wrong" << std::endl;
        return 1;
    }

    sqlite3 *db = db::f(db::FILE_LOGIN);
    Login login{};
    login.load(db, args[0]);
    sqlite3_close(db);

    login.prity_print(std::cout);

    return 0;
}

int login_new(std::span<char*> args) {
    if (args.size() != 2) {
        std::cerr << "[ERROR] new args wrong" << std::endl;
        return 1;
    }

    sqlite3 *db = db::f(db::FILE_LOGIN);
    Login login{};
    std::string_view passwd = std::string_view{args[1]};
    login.create(args[0], passwd);
    login.save(db);
    sqlite3_close(db);

    return 0;
}

typedef int (*main_func)(std::span<char*>);
typedef struct {
    const char *cmd;
    const char *desc;
    main_func func;
} cmd;

constexpr std::array commands = std::to_array<const cmd>({
    {"get", "display salt and the hashes", get},
    {"new", "create new user", login_new},
});

void usage() {
    std::cout << "USAGE: cli <cmd> <cmd args>\n<cmd>:\n";
    for (const cmd command : commands)
        std::cout << "\t" << command.cmd << " - " << command.desc << "\n";
}


int main(int argc, char *argv[]) {

    // char *pw = "awdawd";
    // size_t pw_len = strlen(pw);
    // unsigned char hash[EVP_MAX_MD_SIZE] = {0};

    // SHA512((unsigned char*) pw, pw_len, hash);

    // std::printf("%p : ", hash);
    // for (size_t i = 0; i < EVP_MAX_MD_SIZE; ++i) std::printf("%02X", hash[i]);
    // std::printf("\n");
    // std::cout << pw << std::endl;

    // return 0;

    if (argc <= 1) {
        usage();
        return 1;
    }

    const char *user_cmd = argv[1];
    main_func func = nullptr;

    for (const cmd command : commands) {
        if (0 == strcmp(user_cmd, command.cmd)) {
            func = command.func;
            break;
        }
    }

    if (!func) {
        usage();
        return 1;
    }

    return func(std::span(argv + 2, argc - 2));
}
