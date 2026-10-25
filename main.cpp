#include <iostream>
#include <cstring>
#include <array>

#include <print>

#include "hashing.h"
#include "db.h"

#define SQL_LOGIN_T "login"

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

    std::println(std::cout, "Welcome back {:} !!!", login_from_db.email);
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

typedef int (*main_func)(int argc, char *argv[]);
typedef struct {
    const char *cmd;
    const char *desc;
    main_func func;
} cmd;

constexpr std::array commands = std::to_array<const cmd>({
    {"new", "create new user", main_new},
    {"login", "check if user+password is in the DB", main_login},
    {"get", "display salt and the hashes of a user", main_get},
});

static void
usage() {
    std::cout << "USAGE: cli [OPTIONS] COMMAND\n\nCommands:\n";
    for (const cmd command : commands) {
        std::print(std::cout, "  {:<8} {}\n", command.cmd, command.desc);
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
