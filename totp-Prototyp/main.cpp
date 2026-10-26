

#include <iostream>
#include <string>
#include <ctime>
#include <cstdlib>
#include <oath.h>

int main() {

    // TOTP-Bibliothek starten
    if (oath_init() != OATH_OK) {
        std::cout << "Fehler beim Start.\n";
        return 1;
    }

    // Testdaten für Machbarkeitsnachweis
    std::string testBenutzer = "Ranim";
    std::string testPasswort = "test123";

    // Festes TOTP-Secret nur für Prototyp
    std::string secretBase32 =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    std::string benutzername;
    std::string passwort;
    std::string code;

    std::cout << "       LOGIN MIT 2FA\n";

    // 1. Faktor: Benutzername und Passwort
    std::cout << "Benutzername: ";
    std::getline(std::cin, benutzername);

    std::cout << "Passwort: ";
    std::getline(std::cin, passwort);

    if (benutzername != testBenutzer ||
        passwort != testPasswort) {

        std::cout << "\n Ungueltige Login-Daten!\n";
        std::cout << " Zugriff verweigert.\n";

        oath_done();
        return 0;
    }

    std::cout << "\n Korrekt!\n";
    std::cout << " Zweiter Faktor erforderlich.\n";

    // 2. Faktor: TOTP-Code
    std::cout << "TOTP-Code: ";
    std::getline(std::cin, code);

    // Format des Codes pruefen
    if (code.length() != 6 ||
        code.find_first_not_of("0123456789") !=
        std::string::npos) {

        std::cout << "\nUngueltiges TOTP-Codeformat!\n";
        std::cout << " Zugriff verweigert.\n";

        oath_done();
        return 0;
    }

    // Shared Secret decodieren
    char* secret = nullptr;
    size_t secretLaenge = 0;

    int status = oath_base32_decode(
        secretBase32.c_str(),
        secretBase32.size(),
        &secret,
        &secretLaenge
    );

    if (status != OATH_OK) {
        std::cout << "Fehler beim Secret.\n";
        oath_done();
        return 1;
    }

    // Echten TOTP-Code ueberpruefen
    int ergebnis = oath_totp_validate(
        secret,
        secretLaenge,
        std::time(nullptr),
        30,
        0,
        0,
        code.c_str()
    );

    std::free(secret);

    if (ergebnis < 0) {
        std::cout << "\n TOTP-Code ungueltig!\n";
        std::cout << "Zugriff verweigert.\n";

        oath_done();
        return 0;
    }

    // Beide Faktoren sind korrekt
    std::cout << "\n TOTP-Code gueltig!\n";
    std::cout << " Anmeldung erfolgreich!\n";

    std::cout << "\n GESCHUETZTER BEREICH \n";
    std::cout << "Willkommen, " << benutzername << "!\n";

    oath_done();
    return 0;
}
