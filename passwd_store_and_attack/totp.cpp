// TOTP-Teil (Ranim)
#include "totp.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include <fcntl.h>
#include <unistd.h>

#include <oath.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace totp {

    const constexpr size_t KEY_SIZE = 32; // AES-256 -> 32 Byte Master-Key

    // ---------- Schluesselverwaltung ----------
    // ---------- Master-Key: eigene Datei im Home-Ordner, nicht im Projekt ----------

    // Separate Datei ausserhalb des Projektordners (im Home-Ordner)
    static std::string keyPfad() {
        const char *home = std::getenv("HOME");
        if (home == nullptr) home = ".";
        return std::string(home) + "/.its_totp_master.key";
    }

    static bool masterKeyLaden(uint8_t key[KEY_SIZE]) {
        std::string pfad = keyPfad();

        // Bei spaeteren Programmstarts denselben Master-Key laden
        // Fall 1: Datei gibt es schon -> denselben Key laden
        FILE *datei = std::fopen(pfad.c_str(), "rb");
        if (datei != nullptr) {
            size_t gelesen = std::fread(key, 1, KEY_SIZE, datei);
            std::fclose(datei);
            if (gelesen != KEY_SIZE) {
                std::cout << "Master-Key-Datei ist beschaedigt: " << pfad << "\n";
                return false;
            }
            return true;
        }

        // Master-Key einmalig zufaellig erzeugen
        // Fall 2: erster Start -> neuen zufaelligen Key erzeugen
        if (RAND_bytes(key, KEY_SIZE) != 1) return false;

        // Durch Dateizugriffsrechte geschuetzt speichern
        // 0600 = nur der eigene Benutzer darf die Datei lesen und schreiben
        int fd = open(pfad.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            std::cout << "Master-Key-Datei konnte nicht angelegt werden: " << pfad << "\n";
            return false;
        }
        ssize_t geschrieben = write(fd, key, KEY_SIZE);
        close(fd);
        if (geschrieben != (ssize_t) KEY_SIZE) return false;

        std::cout << "Neuer Master-Key erzeugt: " << pfad << "\n";
        return true;
    }

    // ---------- AES-256-GCM ----------
    // Die E-Mail wird als Zusatzdaten (AAD) mitgeprueft. Dadurch passt ein
    // verschluesseltes Secret nur zu genau diesem Konto.

    // Secret mit dem Master-Key verschluesseln (AES-256-GCM)
    static bool verschluesseln(const uint8_t key[KEY_SIZE], const std::string &email,
                               const uint8_t secret[db::TOTP_SECRET_SIZE], db::Login &login) {
        // Fuer jede Verschluesselung eine neue zufaellige Nonce
        if (RAND_bytes(login.totp_nonce, db::TOTP_NONCE_SIZE) != 1) return false;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) return false;

        bool ok = true;
        int len = 0;
        if (ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, login.totp_nonce) != 1) ok = false;
        if (ok && EVP_EncryptUpdate(ctx, nullptr, &len, (const uint8_t *) email.c_str(), (int) email.size()) != 1) ok = false;
        if (ok && EVP_EncryptUpdate(ctx, login.totp_secret_enc, &len, secret, db::TOTP_SECRET_SIZE) != 1) ok = false;
        if (ok && EVP_EncryptFinal_ex(ctx, login.totp_secret_enc + len, &len) != 1) ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, db::TOTP_TAG_SIZE, login.totp_tag) != 1) ok = false;

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    // Secret entschluesseln
    // Liefert false bei fehlgeschlagener Entschluesselung
    static bool entschluesseln(const uint8_t key[KEY_SIZE], const std::string &email,
                               db::Login &login, uint8_t secret[db::TOTP_SECRET_SIZE]) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) return false;

        bool ok = true;
        int len = 0;
        if (ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, login.totp_nonce) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(ctx, nullptr, &len, (const uint8_t *) email.c_str(), (int) email.size()) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(ctx, secret, &len, login.totp_secret_enc, db::TOTP_SECRET_SIZE) != 1) ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, db::TOTP_TAG_SIZE, login.totp_tag) != 1) ok = false;
        // Hier wird der Tag geprueft: passt er nicht, wurde etwas veraendert
        if (ok && EVP_DecryptFinal_ex(ctx, secret + len, &len) != 1) ok = false;

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    // ---------- Funktionen fuer Registrierung, Login und Recovery ----------

    bool neuesSecretEinrichten(const std::string &email, bool ersetzen) {
        uint8_t key[KEY_SIZE];
        if (!masterKeyLaden(key)) return false;

        // Fuer jedes Benutzerkonto ein eigenes zufaelliges TOTP-Secret erzeugen
        // 1. Zufaelliges Secret erzeugen
        uint8_t secret[db::TOTP_SECRET_SIZE];
        bool ok = RAND_bytes(secret, db::TOTP_SECRET_SIZE) == 1;

        // Secret mit dem Master-Key verschluesseln
        // 2. Mit dem Master-Key verschluesseln
        db::Login login{};
        email.copy(login.email, hashing::EMAIL_SIZE - 1);
        if (ok) ok = verschluesseln(key, email, secret, login);

        // Verschluesseltes Secret, Nonce und Tag beim Benutzerkonto in der Datenbank speichern
        // Bei ersetzen = true wird das alte Secret ersetzt (Recovery)
        // 3. Verschluesseltes Secret, Nonce und Tag beim Konto speichern
        if (ok) {
            db::DB datenbank{};
            ok = datenbank.connect();
            if (ok) {
                ok = datenbank.save_totp(login, ersetzen);
                datenbank.disconnect();
            }
        }

        // Secret als Base32 zur Einrichtung der Authenticator-App anzeigen
        // 4. Erst nach dem Speichern als Base32 fuer die Authenticator-App anzeigen
        if (ok) {
            char *base32 = nullptr;
            size_t base32_laenge = 0;
            if (oath_base32_encode((const char *) secret, db::TOTP_SECRET_SIZE, &base32, &base32_laenge) == OATH_OK) {
                std::cout << "\nTOTP-Secret (in Authenticator-App eintragen): " << base32 << "\n";
                std::free(base32);
            } else {
                ok = false;
            }
        }

        // Klartext-Secret und Key aus dem Speicher loeschen
        OPENSSL_cleanse(secret, sizeof(secret));
        OPENSSL_cleanse(key, sizeof(key));
        return ok;
    }

    bool codeVerbrauchen(const std::string &email, int64_t zeitschritt) {
        db::DB datenbank{};
        if (!datenbank.connect()) return false;
        bool ok = datenbank.use_totp_step(email, zeitschritt);
        datenbank.disconnect();
        return ok;
    }

    bool secretLaden(const std::string &email, uint8_t secret[db::TOTP_SECRET_SIZE]) {
        uint8_t key[KEY_SIZE];
        if (!masterKeyLaden(key)) return false;

        // Verschluesseltes Secret des Benutzerkontos aus der Datenbank laden
        // Verschluesseltes Secret, Nonce und Tag aus der Tabelle login laden
        db::DB datenbank{};
        db::Login login{};
        bool ok = datenbank.connect();
        if (ok) {
            ok = datenbank.load_totp(email, login);
            datenbank.disconnect();
        }
        if (!ok) {
            std::cout << "Kein TOTP-Secret fuer dieses Konto gefunden.\n";
            OPENSSL_cleanse(key, sizeof(key));
            return false;
        }

        // Entschluesseln
        // Fehlgeschlagene Entschluesselung -> false -> Anmeldung wird abgelehnt
        // Entschluesseln (schlaegt fehl bei falschem Key oder manipulierten Daten)
        ok = entschluesseln(key, email, login, secret);
        OPENSSL_cleanse(key, sizeof(key));
        if (!ok) {
            std::cout << "TOTP-Secret konnte nicht entschluesselt werden.\n";
        }
        return ok;
    }

}
