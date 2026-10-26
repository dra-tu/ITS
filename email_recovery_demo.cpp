
#include <chrono>
#include <iostream>
#include <string>
#include <cstdlib>

using Clock = std::chrono::steady_clock;

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

int main() {
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
