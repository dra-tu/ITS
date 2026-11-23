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
#include "totp.h"   // TOTP-Funktionen einbinden
#include <openssl/crypto.h>   // fuer OPENSSL_cleanse
// ENDE TOTP-ERGAENZUNG

// BEGINN RECOVERY-ERGAENZUNG (Dijana)
#include <openssl/rand.h>   // Zufallszahlen fuer den Recovery-Token
// ENDE RECOVERY-ERGAENZUNG

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
        std::cerr << "EXPECTED: cli get <email/user>" << std::endl;
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
static bool pruefeTotp(const std::string& email, const std::string& code) {
    // Nur genau sechs Ziffern zulassen.
    if (code.length() != 6 ||
        code.find_first_not_of("0123456789") != std::string::npos) {
        std::cout << "TOTP-Code muss aus genau sechs Ziffern bestehen.\n";
        return false;
    }

    // Verschluesseltes Secret des Kontos laden und entschluesseln
    //  Ersetzt das bisher fest hinterlegte Test-Secret
    uint8_t secret[db::TOTP_SECRET_SIZE];
    if (!totp::secretLaden(email, secret)) {
        return false;   //  Entschluesselung fehlgeschlagen -> ablehnen
    }

    if (oath_init() != OATH_OK) {
        std::cout << "TOTP-Bibliothek konnte nicht gestartet werden.\n";
        OPENSSL_cleanse(secret, sizeof(secret));
        return false;
    }

    const std::time_t jetzt = std::time(nullptr);

    if (jetzt == static_cast<std::time_t>(-1)) {
        std::cout << "Systemzeit konnte nicht gelesen werden.\n";
        OPENSSL_cleanse(secret, sizeof(secret));
        oath_done();
        return false;
    }

    std::cout
        << "TOTP: 6 Ziffern, feste Zeitabschnitte von 30 Sekunden.\n"
        << "Nur der Code des aktuellen Zeitabschnitts wird akzeptiert.\n";

    //  Eingegebenen Code mit dem benutzerspezifischen Secret und der aktuellen Zeit pruefen
    int ergebnis = oath_totp_validate(
        (const char*) secret,
        sizeof(secret),
        jetzt,
        30,              // Zeitabschnitt: 30 Sekunden
        0,               // Startzeitpunkt: Unix-Epochenbeginn
        0,               // Keine benachbarten Zeitabschnitte pruefen
        code.c_str()
    );

    OPENSSL_cleanse(secret, sizeof(secret));
    oath_done();

    if (ergebnis < 0) {
        return false;   // Ungueltiger Code -> false -> Anmeldung abgelehnt
    }

    // Replay-Schutz: Jeder Code darf nur einmal verwendet werden.
    // Zeitabschnitt = aktuelle Zeit / 30 Sekunden (wie bei der TOTP-Berechnung).
    // Erst NACH einem gueltigen Code markieren, damit falsche Codes nichts verbrauchen.
    const int64_t zeitschritt = jetzt / 30;
    if (!totp::codeVerbrauchen(email, zeitschritt)) {
        std::cout << "Dieser TOTP-Code wurde bereits verwendet. Bitte auf den naechsten Code warten.\n";
        return false;
    }

    return true;
}
// ENDE TOTP-ERGAENZUNG

// BEGINN RECOVERY-ERGAENZUNG (Dijana)
// So lange ist ein Recovery-Token gueltig. Danach ist die Sperre automatisch vorbei.
static constexpr int64_t RECOVERY_TIMEOUT_S = 300;   // 5 Minuten

// Erzeugt einen zufaelligen Token (16 Byte = 128 Bit, als 32 Hex-Zeichen).
static bool
recovery_token_erzeugen(std::string &out_token) {
    uint8_t zufall[16];
    if (RAND_bytes(zufall, sizeof(zufall)) != 1) return false;

    const char hex[] = "0123456789abcdef";
    out_token.clear();
    for (const uint8_t byte : zufall) {
        out_token += hex[byte >> 4];
        out_token += hex[byte & 0x0F];
    }
    return true;
}

static int64_t
jetzt_unix() {
    return static_cast<int64_t>(std::time(nullptr));
}

// true, wenn fuer das Konto eine Recovery-Anfrage laeuft (Token vorhanden und nicht abgelaufen)
static bool
recovery_gesperrt(const db::DB &db, const std::string_view &email) {
    std::array<uint8_t, hashing::SHA512_SIZE> hash{};
    int64_t ablauf = 0;
    if (!db.recovery_load(email, hash, ablauf)) return false;   // keine Anfrage
    return ablauf > jetzt_unix();
}
// ENDE RECOVERY-ERGAENZUNG

static int
main_login(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "[ERROR] login args wrong" << std::endl;
        std::cerr << "EXPECTED: cli login <email/user> <password> <totp>" << std::endl;
        return 1;
    }

    // BEGINN RECOVERY-ERGAENZUNG (Dijana)
    bool totp_abgeschaltet = false;   // nur true nach recover-insecure (Demo)
    // Laeuft gerade eine Recovery, wird der Login komplett abgelehnt
    // (vor der TOTP-Pruefung, damit auch kein TOTP-Code verbraucht wird).
    {
        db::DB lock_db{};
        if (!lock_db.connect()) return 1;
        const bool gesperrt = recovery_gesperrt(lock_db, argv[1]);
        totp_abgeschaltet = lock_db.totp_disable_get(argv[1]);
        lock_db.disconnect();
        if (gesperrt) {
            std::cout << "Account locked: recovery in progress\n";
            return 1;
        }
    }
    // ENDE RECOVERY-ERGAENZUNG

    // Ranim TOTP prüfung
    std::string totp = argv[3];

    // TOTP-Code des Benutzerkontos pruefen, bei Fehler Anmeldung ablehnen
    if (!totp_abgeschaltet && !pruefeTotp(argv[1], totp)) {  // RECOVERY: Demo-Umgehung  // TOTP-Pruefung eingefuegt
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
        std::cout << "Wrong password and or email\n";
        return 1;
    }
}

static int
main_new(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "[ERROR] new args wrong" << std::endl;
        std::cerr << "EXPECTED: cli new <email/user> <password>" << std::endl;
        return 1;
    }

    db::DB db{};
    db::Login login{};

    login.create(argv[1], argv[2]);

    if (!db.connect()) return 1;

    if (!db.save_and_new_totp(login, false)) {
        std::cout << "Benutzer konnte nicht eingerichtet werden.\n";
        return 1;
    }

    db.disconnect();

    return 0;
}

static int
main_attack(int argc, char *argv[]) {
    (void) argc; (void) argv;
    if (argc != 1) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        std::cerr << "EXPECTED: cli attack" << std::endl;
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

// BEGINN RECOVERY-ERGAENZUNG (Dijana)
// cli recover <user>: erklaert die zwei Schritte der Wiederherstellung
static int
main_recover(int argc, char *argv[]) {
    (void) argv;
    if (argc != 2) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        std::cerr << "EXPECTED: cli recover <email/user>" << std::endl;
        return 1;
    }
    std::cout << "Recovery geht in zwei Schritten (wie bei einer echten E-Mail):\n"
              << "  1) cli recover-get <user>\n"
              << "       -> Token wird per (simulierter) E-Mail verschickt, Konto ist gesperrt\n"
              << "  2) cli recover-set <user> <new password> <token>\n"
              << "       -> neues Passwort + neuer TOTP-Code, Sperre wird aufgehoben\n";
    return 0;
}

// Schritt 1: Token erzeugen, Hash in der DB speichern, Konto sperren
static int
main_recover_get(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        std::cerr << "EXPECTED: cli recover-get <user>" << std::endl;
        return 1;
    }

    const std::string user = argv[1];

    db::DB db{};
    db::Login login{};
    if (!db.connect()) return 1;

    // Antwort ist immer gleich, egal ob das Konto existiert (verraet keine Benutzer).
    const char *antwort = "Falls das Konto existiert, wurde eine E-Mail mit einem Token gesendet.\n";

    if (!db.load_login(user, login)) {
        db.disconnect();
        std::cout << antwort;
        return 0;
    }

    // Es gibt schon eine laufende Anfrage -> keine neue, sonst koennte ein Angreifer
    // die Sperre immer wieder verlaengern
    if (recovery_gesperrt(db, user)) {
        db.disconnect();
        std::cerr << "[ERROR] Es laeuft schon eine Recovery. Bitte bis zum Timeout warten.\n";
        return 1;
    }

    std::string token;
    if (!recovery_token_erzeugen(token)) {
        db.disconnect();
        std::cerr << "[ERROR] Token konnte nicht erzeugt werden" << std::endl;
        return 1;
    }

    // In der DB steht nur der Hash des Tokens (wie bei Passwoertern),
    // den Klartext-Token bekommt nur der Benutzer per E-Mail.
    std::array<uint8_t, hashing::SHA512_SIZE> token_hash{};
    if (!hashing::sha512(token, token_hash)) {
        db.disconnect();
        return 1;
    }

    const int64_t ablauf = jetzt_unix() + RECOVERY_TIMEOUT_S;
    const bool ok = db.recovery_start(user, token_hash, ablauf);
    db.disconnect();
    if (!ok) {
        std::cerr << "[ERROR] Recovery konnte nicht gestartet werden" << std::endl;
        return 1;
    }

    std::cout << antwort;
    std::cout << "\n[SIMULIERTE E-MAIL an " << user << "]\n"
              << "Betreff: Kontowiederherstellung\n"
              << "Token (" << RECOVERY_TIMEOUT_S / 60 << " Minuten gueltig): " << token << "\n"
              << "Das Konto ist bis zum Abschluss oder Timeout gesperrt.\n";
    return 0;
}

// Gemeinsame Pruefung fuer recover-set und recover-insecure:
// Gibt es eine Anfrage, ist sie nicht abgelaufen und passt der Token?
static bool
recovery_token_pruefen(const db::DB &db, const std::string &user, const std::string &token) {
    // Alle Fehler zeigen dieselbe Meldung (nicht verraten, was genau falsch war)
    const char *fehler = "[ERROR] Token ungueltig oder abgelaufen\n";

    std::array<uint8_t, hashing::SHA512_SIZE> gespeichert{};
    int64_t ablauf = 0;
    if (!db.recovery_load(user, gespeichert, ablauf)) {
        std::cerr << fehler;
        return false;
    }
    if (ablauf <= jetzt_unix()) {
        db.recovery_clear(user);   // abgelaufen -> Sperre aufheben
        std::cerr << fehler;
        return false;
    }

    // Hash des eingegebenen Tokens mit dem gespeicherten vergleichen.
    // CRYPTO_memcmp braucht immer gleich lange (kein Timing-Leck wie bei memcmp).
    std::array<uint8_t, hashing::SHA512_SIZE> eingegeben{};
    if (!hashing::sha512(token, eingegeben)) return false;
    if (CRYPTO_memcmp(eingegeben.data(), gespeichert.data(), hashing::SHA512_SIZE) != 0) {
        std::cerr << fehler;
        return false;
    }
    return true;
}

// Schritt 2 (SICHER): Token pruefen, neues Passwort + neuen TOTP-Code speichern, Sperre aufheben
static int
main_recover_set(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        std::cerr << "EXPECTED: cli recover-set <user> <new password> <token>" << std::endl;
        return 1;
    }

    const std::string user     = argv[1];
    const std::string password = argv[2];
    const std::string token    = argv[3];

    db::DB db{};
    if (!db.connect()) return 1;

    // 1+2. Anfrage und Token pruefen
    if (!recovery_token_pruefen(db, user, token)) {
        db.disconnect();
        return 1;
    }

    // 3. Neue Passwort-Hashes (mit neuem Salt) berechnen und speichern
    db::Login neu{};
    if (!neu.create(user, password)) {
        db.disconnect();
        std::cerr << "[ERROR] Passwort konnte nicht gehasht werden" << std::endl;
        return 1;
    }

    if (!db.save_and_new_totp(neu, true)) {
        db.disconnect();
        std::cerr << "[ERROR] Benutzer konnte nicht bearbeitet werden. Token bleibt gueltig, bitte nochmal versuchen.\n";
        return 1;
    }

    // 5. Token loeschen -> einmal benutzbar, Konto ist wieder entsperrt (2FA wieder aktiv)
    db.recovery_clear(user, true);
    db.disconnect();

    std::cout << "Recovery abgeschlossen: neues Passwort gesetzt, Konto entsperrt.\n";
    return 0;
}

// DEMO "Verlust des zweiten Faktors": das TOTP-Secret wird unbrauchbar.
// Danach kann sich der Benutzer trotz richtigem Passwort nicht mehr anmelden.
static int
main_lose_totp(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        std::cerr << "EXPECTED: cli lose-totp <user>" << std::endl;
        return 1;
    }

    db::DB db{};
    if (!db.connect()) return 1;
    const bool ok = db.totp_lose(argv[1]);
    db.disconnect();

    if (!ok) {
        std::cerr << "[ERROR] Benutzer nicht gefunden oder hat kein TOTP-Secret" << std::endl;
        return 1;
    }
    std::cout << "Handy verloren: das TOTP-Secret von " << argv[1] << " ist nicht mehr nutzbar.\n"
              << "Login mit Passwort + TOTP geht jetzt nicht mehr -> Recovery noetig.\n";
    return 0;
}

// DEMO "UNSICHERE Wiederherstellung": der E-Mail-Token allein reicht, und das System
// schaltet 2FA einfach ab, statt ein neues TOTP-Secret auszugeben.
// Wer das Postfach kontrolliert (Angreifer), braucht danach nur noch das Passwort.
static int
main_recover_insecure(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "[ERROR] args wrong" << std::endl;
        std::cerr << "EXPECTED: cli recover-insecure <user> <new password> <token>" << std::endl;
        return 1;
    }

    const std::string user     = argv[1];
    const std::string password = argv[2];
    const std::string token    = argv[3];

    db::DB db{};
    if (!db.connect()) return 1;

    if (!recovery_token_pruefen(db, user, token)) {
        db.disconnect();
        return 1;
    }

    db::Login neu{};
    if (!neu.create(user, password)) {
        db.disconnect();
        std::cerr << "[ERROR] Passwort konnte nicht gehasht werden" << std::endl;
        return 1;
    }
    db.update_login(neu);

    // UNSICHER: zweiter Faktor wird abgeschaltet, ohne dass ein TOTP-Code vorgelegt wurde
    db.totp_disable_set(user, true);
    db.recovery_clear(user);
    db.disconnect();

    std::cout << "[UNSICHERE VARIANTE] Passwort gesetzt und 2FA abgeschaltet.\n"
              << "Login geht jetzt nur mit dem Passwort (TOTP-Code wird ignoriert).\n"
              << "Wer nur das E-Mail-Postfach hat, umgeht damit die Zwei-Faktor-Authentifizierung.\n";
    return 0;
}
// ENDE RECOVERY-ERGAENZUNG

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
    // BEGINN RECOVERY-ERGAENZUNG (Dijana)
    {"recover",     "<email/user>  show the recovery steps",                      main_recover},
    {"recover-get", "<user>  start recovery: get token, lock user",               main_recover_get},
    {"recover-set", "<user> <new password> <token>  finish: new password + totp", main_recover_set},
    {"lose-totp",   "<user>  demo: simulate loss of the second factor",           main_lose_totp},
    {"recover-insecure", "<user> <new password> <token>  demo: INSECURE, disables 2FA", main_recover_insecure},
    // ENDE RECOVERY-ERGAENZUNG
});

static void
usage() {
    std::cout << "USAGE: cli [OPTIONS] COMMAND\n\nCommands:\n";
    for (const cmd command : commands) {
        std::printf("  %-16s %s\n", command.cmd, command.desc);   // RECOVERY: Breite 8 -> 16 wegen recover-get
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
