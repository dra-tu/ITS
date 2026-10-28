#include <iostream>
#include <cstring>
#include <array>

#include <print>
#include <sqlite3.h>

#include "hashing.h"
#include "db.h"
#include "rainbow.h"

#include <chrono>
// BEGINN TOTP-ERGAENZUNG
#include <string>
#include <ctime>
#include <cstdlib>
#include <oath.h>
// ENDE TOTP-ERGAENZUNG

using Clock = std::chrono::steady_clock;

#define SQL_LOGIN_T "login"

namespace rainbow {
    std::array<std::array<uint8_t, hashing::SHA512_SIZE>, passwd.size()> sha512{};

    void fill_sha512() {
        for (size_t i = 0; i < passwd.size(); ++i) {
            hashing::sha512(passwd[i], sha512[i]);
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
// BEGINN TOTP-ERGAENZUNG
static bool pruefeTotp(const std::string& code) {
    // Festes Test-Secret fuer den Prototyp.
    // Keine Speicherung in der Datenbank.
    const std::string secretBase32 =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    // Nur genau sechs Ziffern zulassen.
    if (code.length() != 6 ||
        code.find_first_not_of("0123456789") != std::string::npos) {
        std::cout << "TOTP-Code muss aus genau sechs Ziffern bestehen.\n";
        return false;
        }

    if (oath_init() != OATH_OK) {
        std::cout << "TOTP-Bibliothek konnte nicht gestartet werden.\n";
        return false;
    }

    // Base32-Darstellung in die Schluesselbytes umwandeln.
    char* secret = nullptr;
    std::size_t secretLaenge = 0;

    int status = oath_base32_decode(
        secretBase32.c_str(),
        secretBase32.size(),
        &secret,
        &secretLaenge
    );

    if (status != OATH_OK) {
        std::cout << "TOTP-Secret konnte nicht decodiert werden.\n";
        oath_done();
        return false;
    }

    const std::time_t jetzt = std::time(nullptr);

    if (jetzt == static_cast<std::time_t>(-1)) {
        std::cout << "Systemzeit konnte nicht gelesen werden.\n";
        std::free(secret);
        oath_done();
        return false;
    }

    std::cout
        << "TOTP: 6 Ziffern, feste Zeitabschnitte von 30 Sekunden.\n"
        << "Nur der Code des aktuellen Zeitabschnitts wird akzeptiert.\n";

    int ergebnis = oath_totp_validate(
        secret,
        secretLaenge,
        jetzt,
        30,              // Zeitabschnitt: 30 Sekunden
        0,               // Startzeitpunkt: Unix-Epochenbeginn
        0,               // Keine benachbarten Zeitabschnitte pruefen
        code.c_str()
    );

    std::free(secret);
    oath_done();

    return ergebnis >= 0;
}
// ENDE TOTP-ERGAENZUNG
static int
main_login(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "[ERROR] login args wrong" << std::endl;
        return 1;
    }

    // Ranim TOTP prüfung
    std::string totp = argv[3];

    if (!pruefeTotp(totp)) {  // TOTP-Pruefung eingefuegt
        std::cout << "Wrong totp\n";
        return 1;
    }

    db::DB db{};
    db::Login login_from_db{};
    db::Login login_from_user{};

    db.connect();
    db.load_login(argv[1], login_from_db);
    db.disconnect();

    login_from_user.create(argv[1], argv[2], login_from_db.salt);

    if (login_from_db == login_from_user) {
        std::cout << "Welcome back " << login_from_db.email << " !!!";
        return 0;
    } else {
        std::cout << "Wrong password and or email";
        return 1;
    }
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
static void
attack(const std::string& tag,
       sqlite3 *db, std::string sql,
       bool check_salt,
       std::span<uint8_t> hash_buf, HASH_FUNC hash_func) {
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

static void
attack_sha512(sqlite3 *db) {
    std::array<uint8_t, hashing::SHA512_SIZE> hash_buf{};

    attack("sha512", db, "SELECT email, sha512_NoSalt FROM login", false, hash_buf,
    [](size_t &i, const std::string_view &pw, std::span<uint8_t> &salt, std::span<uint8_t> &hash_buf) {
        (void) pw; (void) salt;
        memcpy(hash_buf.data(), rainbow::sha512[i].data(), hashing::SHA512_SIZE);
    });
}

static void
attack_sha512_salt(sqlite3 *db) {
    std::array<uint8_t, hashing::SHA512_SIZE> hash_buf{};

    attack("sha512-salt", db, "SELECT email, sha512_salt, salt FROM login", true, hash_buf,
    [](size_t &i, const std::string_view &pw, std::span<uint8_t> &salt, std::span<uint8_t> &hash_buf) {
        (void) i;
        std::span<uint8_t, hashing::SHA512_SIZE> cal_hash(hash_buf.data(), hashing::SHA512_SIZE);
        std::span<uint8_t, hashing::SALT_SIZE> salt_span(salt.data(), hashing::SALT_SIZE);
        hashing::sha512(pw, salt_span, cal_hash);
    });
}

static void
attack_argon2id(sqlite3 *db) {
    std::array<uint8_t, hashing::ARGON2ID_SIZE> hash_buf{};

    attack("argon2id", db, "SELECT email, argon2id, salt FROM login", true, hash_buf,
    [](size_t &i, const std::string_view &pw, std::span<uint8_t> &salt, std::span<uint8_t> &hash_buf) {
        (void) i;
        std::span<uint8_t, hashing::ARGON2ID_SIZE> cal_hash(hash_buf.data(), hashing::ARGON2ID_SIZE);
        std::span<uint8_t, hashing::SALT_SIZE> salt_span(salt.data(), hashing::SALT_SIZE);
        hashing::argon2id(pw, salt_span, cal_hash);
    });
}

static int
main_attack(int argc, char *argv[]) {
    (void) argc; (void) argv;
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

struct RecoveryRequest {
    std::string token;
    Clock::time_point createdAt;
    bool used = false;
};

// Erstellt einen Token mit 32 hexadezimalen Zeichen.
// arc4random_uniform verwendet den Zufallszahlengenerator des Betriebssystems.
std::string createToken() {
    const char chars[] = "0123456789abcdef";
    std::string token;

    for (int i = 0; i < 32; ++i) {
        token += chars[arc4random_uniform(16)];
    }

    return token;
}

int main_email(int argc, char *argv[]) {
    const std::string username = "Ranim";
    const std::string email = "ranim.test@example.com";
    bool secondFactorEnabled = true;

    RecoveryRequest request;

    std::cout << "=== E-Mail-Kontowiederherstellung: Demo ===\n";
    std::cout << "Testkonto: " << username << "\n";
    std::cout << "1) Normaler Login (Status anzeigen)\n";
    std::cout << "2) Verlust des zweiten Faktors simulieren\n";
    std::cout << "Auswahl: ";

    std::string choice;
    std::getline(std::cin, choice);

    if (choice != "2") {
        std::cout << "Zweiter Faktor ist: "
                  << (secondFactorEnabled ? "AKTIV" : "INAKTIV")
                  << "\n";
        std::cout << "Zum Login werden Passwort und TOTP benoetigt.\n";
        return 0;
    }

    std::cout << "\nDer Benutzer meldet den Verlust des zweiten Faktors.\n";
    std::cout << "Wiederherstellungs-E-Mail: " << email << "\n";

    request.token = createToken();
    request.createdAt = Clock::now();

    const std::string recoveryLink =
        "https://example.invalid/recover?token=" + request.token;

    std::cout << "\n[SIMULIERTE E-MAIL]\n";
    std::cout << "Betreff: Kontowiederherstellung\n";
    std::cout << "Test-Link (1 Minute gueltig):\n";
    std::cout << recoveryLink << "\n";

    // Erste Eingabe: Token pruefen
    std::string submittedToken;

    while (true) {
        std::cout << "\nToken eingeben: ";
        std::getline(std::cin, submittedToken);

        if (request.used) {
            std::cout << "FEHLER: Dieser Link wurde bereits verwendet.\n";
            continue;
        }

        if (Clock::now() - request.createdAt >
            std::chrono::minutes(1)) {
            std::cout << "FEHLER: Der Wiederherstellungs-Link ist abgelaufen.\n";
            return 0;
        }

        if (submittedToken != request.token) {
            std::cout << "FEHLER: Ungueltiger Wiederherstellungs-Link.\n";
            continue;
        }

        // Token wird nach erfolgreicher Pruefung verbraucht.
        request.used = true;
        std::cout << "\nE-Mail-Link bestaetigt.\n";
        break;
    }

    std::cout << "\n[UNSICHERE DEMO-VARIANTE]\n";
    std::cout << "Das System setzt die Zwei-Faktor-Anforderung zurueck,\n";
    std::cout << "obwohl kein TOTP-Code vorgelegt wurde.\n";

    secondFactorEnabled = false;

    std::cout << "Wiederherstellung abgeschlossen. TOTP ist nun: "
              << (secondFactorEnabled ? "AKTIV" : "INAKTIV") << "\n";

    // Zweite Eingabe: Demonstriert, dass derselbe Token verbraucht ist.
    std::cout << "\nTest: Verwende denselben Token erneut.\n";
    std::cout << "Token erneut eingeben: ";
    std::getline(std::cin, submittedToken);

    if (request.used) {
        std::cout << "FEHLER: Dieser Link wurde bereits verwendet.\n";
    }

    std::cout << "\nHinweis: Keine echte E-Mail, keine produktive Anwendung.\n";

    return 0;
}

typedef int (*main_func)(int argc, char *argv[]);
typedef struct {
    const char *cmd;
    const char *desc;
    main_func func;
} cmd;

constexpr std::array commands = std::to_array<const cmd>({
    {"new",    "create new user",                      main_new},
    {"login",  "check if user+password is in the DB",  main_login},
    {"get",    "display salt and the hashes of a user",main_get},
    {"attack", "benchmark offline attacks",          main_attack},
    {"r",     "email",   main_email},
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
