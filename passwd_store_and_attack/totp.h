#pragma once
// TOTP-Teil (Ranim)

#include <string>

#include "db.h"

namespace totp {

    bool neuesSecretEinrichten(const std::string &email, bool ersetzen);

    bool secretLaden(const std::string &email, uint8_t secret[db::TOTP_SECRET_SIZE]);

    bool codeVerbrauchen(const std::string &email, int64_t zeitschritt);

}
