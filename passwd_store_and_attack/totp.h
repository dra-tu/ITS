#pragma once
// TOTP-Teil (Ranim)

#include <string>

#include "db.h"

namespace totp {

    // Erzeugt ein neues zufaelliges TOTP-Secret, verschluesselt es mit AES-256-GCM,
    // speichert es beim Konto in der Tabelle login und zeigt es als Base32 an.
    // ersetzen = false -> Registrierung (ein vorhandenes Secret wird NICHT ueberschrieben)
    // ersetzen = true  -> Recovery (altes Secret wird durch ein neues ersetzt)
    // Registrierung
    // Schnittstelle fuer Recovery (ersetzen = true)
    bool neuesSecretEinrichten(const std::string &email, bool ersetzen);

    // Laedt das verschluesselte Secret des Kontos und entschluesselt es.
    // false, wenn kein Secret vorhanden ist oder die Entschluesselung fehlschlaegt.
    // Login: Secret laden und entschluesseln
    bool secretLaden(const std::string &email, uint8_t secret[db::TOTP_SECRET_SIZE]);

    // Replay-Schutz: Markiert den Zeitabschnitt eines gueltigen Codes als verbraucht.
    // false, wenn ein Code aus diesem Zeitabschnitt schon einmal benutzt wurde.
    bool codeVerbrauchen(const std::string &email, int64_t zeitschritt);

}
