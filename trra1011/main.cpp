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

static bool
check_row(std::string_view email, std::span<uint8_t> hash, size_t hash_expected_size,
          std::span<uint8_t> salt = std::span<uint8_t>{},
          bool check_salt = false) {
    if (!email.data() || !hash.data() || (check_salt && !salt.data())) {
        std::cerr << "[WARNING] salt or sha512_Salt or email field is missing\n";
        return false;
    }
    if (email.size() >= hashing::EMAIL_SIZE) {
        std::cerr << "[WARNING] email: " << email << " is to long\n";
        return false;
    }
    if (hash.size() != hash_expected_size) {
        std::cerr << "[WARNING] hash for " << email << " has wrong size\n";
        return false;
    }
    if (check_salt && (salt.size() != hashing::SALT_SIZE)) {
        std::cerr << "[WARNING] salt for " << email << " has wrong size\n";
        return false;
    }
    return true;
}

static void
attack_sha512(sqlite3 *db) {
    sqlite3_stmt *stmt = nullptr;
    int res = sqlite3_prepare_v2(db, "SELECT email, sha512_NoSalt FROM login", -1, &stmt, nullptr);
    if (res) {
        std::cerr << "[ERROR@" << __func__ << "] " << sqlite3_errmsg(db) << "\n";
        return;
    }

    size_t found   = 0;
    size_t total   = 0;
    size_t skipped = 0;
    while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::string_view email{(char*) sqlite3_column_blob(stmt, 0), (size_t) sqlite3_column_bytes(stmt, 0)};
        std::span hash{(uint8_t*) sqlite3_column_blob(stmt, 1), (size_t) sqlite3_column_bytes(stmt, 1)};
        total++;

        if (!check_row(email, hash, hashing::SHA512_SIZE)) {
            skipped++;
            continue;
        }

        for (size_t i = 0; i < rainbow::passwd.size(); ++i) {
            if (memcmp(&rainbow::sha512[i], hash.data(), hashing::SHA512_SIZE) == 0) {
                std::printf("login \"%s\" \"%s\"\n", email.data(), rainbow::passwd[i]);
                found++;
                break;
            }
        }
    }
    if (res != SQLITE_DONE) {
        std::cerr << "[ERROR@" << __func__ << "] fror sqlite3 " << sqlite3_errmsg(db) << "\n";
    }
    sqlite3_finalize(stmt);

    std::printf("sha512> %3ld/%3ld (skipped: %ld)\n\n", found, total, skipped);
}

static void
attack_sha512_salt(sqlite3 *db) {
    sqlite3_stmt *stmt = nullptr;
    int res = sqlite3_prepare_v2(db, "SELECT email, sha512_salt, salt FROM login", -1, &stmt, nullptr);
    if (res) {
        std::cerr << "[ERROR@" << __func__ << "] " << sqlite3_errmsg(db) << "\n";
        return;
    }

    size_t found   = 0;
    size_t total   = 0;
    size_t skipped = 0;
    while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::string_view email{(char*) sqlite3_column_blob(stmt, 0), (size_t) sqlite3_column_bytes(stmt, 0)};
        std::span hash{(uint8_t*) sqlite3_column_blob(stmt, 1), (size_t) sqlite3_column_bytes(stmt, 1)};
        std::span salt{(uint8_t*) sqlite3_column_blob(stmt, 2), (size_t) sqlite3_column_bytes(stmt, 2)};
        total++;

        if (!check_row(email, hash, hashing::SHA512_SIZE, salt, true)) {
            skipped++;
            continue;
        }

        for (const std::string_view passwd : rainbow::passwd) {
            uint8_t cal_hash[hashing::SHA512_SIZE];
            std::span<uint8_t, hashing::SALT_SIZE> salt_span(salt);
            hashing::sha512(passwd, salt_span, cal_hash);

            if (memcmp(cal_hash, hash.data(), hashing::SHA512_SIZE) == 0) {
                std::printf("login \"%s\" \"%s\"\n", email.data(), passwd.data());
                found++;
                break;
            }
        }
    }
    if (res != SQLITE_DONE) {
        std::cerr << "[ERROR@" << __func__ << "] fror sqlite3 " << sqlite3_errmsg(db) << "\n";
    }
    sqlite3_finalize(stmt);

    std::printf("sha512-salt> %3ld/%3ld (skipped: %ld)\n\n", found, total, skipped);
}

static void
attack_argon2id(sqlite3 *db) {
    sqlite3_stmt *stmt = nullptr;
    int res = sqlite3_prepare_v2(db, "SELECT email, argon2id, salt FROM login", -1, &stmt, nullptr);
    if (res) {
        std::cerr << "[ERROR@" << __func__ << "] " << sqlite3_errmsg(db) << "\n";
        return;
    }

    size_t found   = 0;
    size_t total   = 0;
    size_t skipped = 0;
    while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::string_view email{(char*) sqlite3_column_blob(stmt, 0), (size_t) sqlite3_column_bytes(stmt, 0)};
        std::span hash{(uint8_t*) sqlite3_column_blob(stmt, 1), (size_t) sqlite3_column_bytes(stmt, 1)};
        std::span salt{(uint8_t*) sqlite3_column_blob(stmt, 2), (size_t) sqlite3_column_bytes(stmt, 2)};
        total++;

        if (!check_row(email, hash, hashing::ARGON2ID_SIZE, salt,true)) {
            skipped++;
            continue;
        }

        for (const std::string_view passwd : rainbow::passwd) {
            uint8_t cal_hash[hashing::ARGON2ID_SIZE];
            std::span<uint8_t, hashing::SALT_SIZE> salt_span(salt);
            hashing::argon2id(passwd, salt_span, cal_hash);

            if (memcmp(cal_hash, hash.data(), hashing::ARGON2ID_SIZE) == 0) {
                std::printf("login \"%s\" \"%s\"\n", email.data(), passwd.data());
                found++;
                break;
            }
        }
    }
    if (res != SQLITE_DONE) {
        std::cerr << "[ERROR@" << __func__ << "] fror sqlite3 " << sqlite3_errmsg(db) << "\n";
    }
    sqlite3_finalize(stmt);

    std::printf("argon2id> %3ld/%3ld (skipped: %ld)\n\n", found, total, skipped);
}

static int
main_attack(int argc, char *argv[]) {
    rainbow::fill_sha512();

    sqlite3 *db_attack = nullptr;
    if (sqlite3_open(db::DEFAULT_DB_FILE, &db_attack) != SQLITE_OK) {
        std::cerr << "[ERROR@" << __func__ << "] opening db (" << sqlite3_errmsg(db_attack) << ")\n";
        sqlite3_close(db_attack);
        return false;
    }

    attack_sha512(db_attack);
    attack_sha512_salt(db_attack);
    attack_argon2id(db_attack);

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
