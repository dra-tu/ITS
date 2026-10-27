#include <iostream>
#include <cstring>
#include <array>

#include <print>
#include <sqlite3.h>

#include "hashing.h"
#include "db.h"
#include "rainbow.h"

#define SQL_LOGIN_T "login"

namespace rainbow {
    std::array<std::array<uint8_t, hashing::SHA512_SIZE>, passwd.size()> sha512{};

    void fill_sha512() {
        for (size_t i = 0; i < passwd.size(); ++i) {
            std::span sha512_span(sha512[i]);
            hashing::sha512(passwd[i], sha512_span);
        }
    }
}

static int
main_get(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "[ERROR] get args wrong" << std::endl;
        return 1;
    }

    db::DB db;
    db::Login login{};

    db.connect();
    db.load_login(argv[1], login);
    db.disconnect();

    login.pretty_print(std::cout);

    return 0;
}

static int
main_login(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "[ERROR] login args wrong" << std::endl;
        return 1;
    }

    db::DB db{};
    db::Login login_from_db{};
    db::Login login_from_user{};

    db.connect();
    db.load_login(argv[1], login_from_db);
    db.disconnect();

    login_from_user.create(argv[1], argv[2], login_from_db.salt);

    if (login_from_db != login_from_user) {
        std::println(std::cout, "Wrong password and or email");
        return 1;
    }

    std::cout << "Welcome back " << login_from_db.email << " !!!";
    return 0;
}

static int
main_new(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "[ERROR] new args wrong" << std::endl;
        return 1;
    }

    db::DB db{};
    db::Login login{};

    db.connect();
    login.create(argv[1], argv[2]);
    db.save_login(login);
    db.disconnect();

    return 0;
}

static int
main_attack(int argc, char *argv[]) {
    std::cout << "[WARNING] this function is not good" << std::endl;
    if (argc != 3) {
        std::cout << "USAGE: <attack DB> <rt DB>" << std::endl;
        return 1;
    }

    rainbow::fill_sha512();

    const char* db_attack_path = argv[1];

    const char *sql_sha512      = "SELECT email, sha512_NoSalt FROM login";
    const char *sql_sha512_salt = "SELECT email, salt, sha512_salt FROM login";
    const char *sql_argon2id    = "SELECT email, salt, argon2id FROM login";

    sqlite3 *db_attack = nullptr;
    if (sqlite3_open(db_attack_path, &db_attack) != SQLITE_OK) {
        std::cout << "[ERROR][SQLITE3] " << sqlite3_errmsg(db_attack) << std::endl;
        sqlite3_close(db_attack);
        return false;
    }

    sqlite3_stmt *stmt = nullptr;
    int res = 0;

    // crack sha512
    std::cout << "== sha512 ==" << std::endl;
    stmt = nullptr;
    res = sqlite3_prepare_v2(db_attack, sql_sha512, -1, &stmt, nullptr);
    if (res) { std::cout << sqlite3_errmsg(db_attack) << "\n"; return false; }
    while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
        char    *db_email = (char*) sqlite3_column_blob(stmt, 0);
        uint8_t *db_hash  = (uint8_t*) sqlite3_column_blob(stmt, 1);

        for (size_t j = 0; j < rainbow::passwd.size(); ++j) {
            if (memcmp(&rainbow::sha512[j], db_hash, (size_t)sqlite3_column_bytes(stmt, 1)) == 0) {
                std::cout << db_email << " --- " << rainbow::passwd[j] << "\n";
                break;
            }
        }
    }
    if (res != SQLITE_DONE) std::cerr << sqlite3_errmsg(db_attack) << "\n";
    sqlite3_finalize(stmt);

    // crack sha512 -- salt
    std::cout << "== sha512 SALT ==" << std::endl;
    stmt = nullptr;
    res = sqlite3_prepare_v2(db_attack, sql_sha512_salt, -1, &stmt, nullptr);
    if (res) { std::cout << sqlite3_errmsg(db_attack) << "\n"; return false; }
    while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
        char    *db_email = (char*) sqlite3_column_blob(stmt, 0);
        uint8_t *db_salt  = (uint8_t*) sqlite3_column_blob(stmt, 1);
        uint8_t *db_hash  = (uint8_t*) sqlite3_column_blob(stmt, 2);

        for (const std::string_view passwd : rainbow::passwd) {
            uint8_t cal_hash[hashing::SHA512_SIZE];

            std::span hash_span(cal_hash);
            std::span salt_span(db_salt, hashing::SALT_SIZE);
            hashing::sha512(passwd, salt_span, hash_span);

            if (memcmp(cal_hash, db_hash, (size_t)sqlite3_column_bytes(stmt, 2)) == 0) {
                std::cout << db_email << " --- " << passwd << "\n";
                break;
            }
        }
    }
    if (res != SQLITE_DONE) std::cerr << sqlite3_errmsg(db_attack) << "\n";
    sqlite3_finalize(stmt);

    // crack sha512 -- argon2id
    std::cout << "== argon2id ==" << std::endl;
    stmt = nullptr;
    res = sqlite3_prepare_v2(db_attack, sql_argon2id, -1, &stmt, nullptr);
    if (res) { std::cout << sqlite3_errmsg(db_attack) << "\n"; return false; }
    while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
        char    *db_email = (char*) sqlite3_column_blob(stmt, 0);
        uint8_t *db_salt  = (uint8_t*) sqlite3_column_blob(stmt, 1);
        uint8_t *db_hash  = (uint8_t*) sqlite3_column_blob(stmt, 2);

        for (const std::string_view passwd : rainbow::passwd) {
            uint8_t cal_hash[hashing::ARGON2ID_SIZE];

            std::span hash_span(cal_hash);
            std::span<uint8_t, hashing::SALT_SIZE> salt_span(db_salt, hashing::SALT_SIZE);
            hashing::argon2id(passwd, salt_span, hash_span);

            if (memcmp(cal_hash, db_hash, (size_t)sqlite3_column_bytes(stmt, 2)) == 0) {
                std::cout << db_email << " --- " << passwd << "\n";
                break;
            }
        }
    }
    if (res != SQLITE_DONE) std::cerr << sqlite3_errmsg(db_attack) << "\n";
    sqlite3_finalize(stmt);

    sqlite3_close(db_attack);

    return 0;
}

typedef int (*main_func)(int argc, char *argv[]);
typedef struct {
    const char *cmd;
    const char *desc;
    main_func func;
} cmd;

constexpr std::array commands = std::to_array<const cmd>({
    {"new",    "create new user",                                               main_new},
    {"login",  "check if user+password is in the DB",                           main_login},
    {"get",    "display salt and the hashes of a user",                         main_get},
    {"attack", "[TODO] benchmark offline attacks",                              main_attack},
});

static void
usage() {
    std::cout << "USAGE: cli [OPTIONS] COMMAND\n\nCommands:\n";
    for (const cmd command : commands) {
        std::printf("  %-8s %s\n", command.cmd, command.desc);
    }
}


int
main(int argc, char *argv[]) {
    if (argc <= 1) { usage(); return 1; }

    const char *user_cmd = argv[1];
    main_func func = nullptr;

    for (const cmd &command : commands) {
        if (0 == strcmp(user_cmd, command.cmd)) {
            func = command.func;
            break;
        }
    }

    if (!func) { usage(); return 1; }

    argv[1] = argv[0];
    argv = &argv[1];
    argc--;

    return func(argc, argv);
}
