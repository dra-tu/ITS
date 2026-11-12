#include <iostream>
#include <cstring>
#include <array>

#include "hashing.h"
#include "db.h"
#include "rainbow.h"

#include <chrono>
using Clock = std::chrono::steady_clock;

// BEGINN TOTP-ERGAENZUNG
#include <string>
#include <ctime>
#include <cstdlib>
#include <oath.h>
// ENDE TOTP-ERGAENZUNG

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

    if (!db.connect()) return 1;
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

    if (!db.connect()) return 1;
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

    if (!db.connect()) return 1;
    login.create(argv[1], argv[2]);

    /// ==================================================
    /// use ONLY one off the next two lines !!!!!!!!!!!

    db.save_login(login);
    // db.update_login(login);

    /// ==================================================

    db.disconnect();

    return 0;
}

static int
main_attack(int argc, char *argv[]) {
    (void) argc; (void) argv;
    if (argc != 1) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        return 1;
    }

    db::DB db;
    if (!db.connect()) return 1;
    db.attack();
    db.disconnect();

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

static int
main_email(int argc, char *argv[]) {
    (void) argc; (void) argv;
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

static int
main_recover_get(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        std::cerr << "EXPECTED: cli <user>" << std::endl;
        return 1;
    }

    std::string user = argv[1];

    return 0;
}

static int
main_recover_set(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        std::cerr << "EXPECTED: cli <user> <new password> <token>" << std::endl;
        return 1;
    }

    std::string user     = argv[1];
    std::string password = argv[2];
    std::string token    = argv[3];

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
    {"recover-get",     "start recovery process",   main_recover_get},
    {"recover-set",     "finish recovery process",   main_recover_set},
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
