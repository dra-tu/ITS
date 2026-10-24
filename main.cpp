#include <iostream>
#include <cstring>
#include <array>
#include <span>

#include <sqlite3.h>

// evp stuff for hash
// #include <openssl/evp.h>

// specific hash functino
// #include <openssl/sha.h>
// #include <openssl/whrlpool.h>

/* hash sha256 example (duck.ai)
 * unsigned char hash[SHA256_DIGEST_LENGTH];
 * SHA256(reinterpret_cast<unsigned char*>(const_cast<char*>(str)),
 *        std::strlen(str),
 *        hash);
 **/

class Login {
public:
    static int main(std::span<char*>) {
        return 0;
    }
};

class Signup {
public:
    static int main(std::span<char*>) {
        return 0;
    }
};

typedef int (*main_func)(std::span<char*>);
typedef struct {
    const char *cmd;
    const char *desc;
    main_func func;
} cmd;

constexpr std::array commands = std::to_array<const cmd>({
    {"login", "", Login::main},
    {"new", "create new user", Signup::main},
});

void usage() {
    std::cout << "USAGE: cli <cmd> <cmd args>\n<cmd>:\n";
    for (const cmd command : commands)
        std::cout << "\t" << command.cmd << " - " << command.desc << "\n";
}

int main(int argc, char *argv[]) {
    const char *filename = "passwd";
    sqlite3 *db = nullptr;
    sqlite3_stmt *stmt = nullptr;

    if (SQLITE_OK != sqlite3_open(filename, &db)) {
        std::cout << "not connected";
        return 1;
    }

    if (sqlite3_prepare_v2(db, "SELECT * FROM passwd",
        -1, &stmt, nullptr
    )) {
        std::cerr << sqlite3_errmsg(db);
        return 1;
    }

    // int user_idx = sqlite3_bind_parameter_index(stmt, ":USER");
    // if (!user_idx) return 1;
    // if (SQLITE_OK != sqlite3_bind_text(stmt, user_idx, "dude", -1, SQLITE_STATIC)) {
    //     std::cerr << sqlite3_errmsg(db);
    //     return 1;
    // }

    int res = 0;
    while ((res = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::cout << "user: " << sqlite3_column_text(stmt, 0) << std::endl;
        std::cout << "pass: " << sqlite3_column_text(stmt, 1) << std::endl;
    }
    if (res != SQLITE_DONE) {
        std::cerr << sqlite3_errmsg(db);
        return 1;
    }
    sqlite3_finalize(stmt);

    return 0;

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