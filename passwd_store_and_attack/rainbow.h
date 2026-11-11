#pragma once

#include "hashing.h"

namespace rainbow {
	// reverence:
	// https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt
	// https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/Language-Specific/German_Pwdb_common-password-list-top-150.txt
	// https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt
	constexpr std::array passwd{
		"login",    "passwort",   "123",    "123456",        "password",  "1234567", "345678",    "1234",     "qwerty",   "Praise the Sun",
		"12345",    "Fireball",   "pussy",  "baseball",      "football",  "letmein",  "monkey",  "696969",    "abc123",   "mustang",
		"sandra",   "pokemon",    "marcel", "Passwort",      "thomas",    "hamburg",  "dragon",  "christian", "bayern",   "geheim",
		"handball", "dortmund",   "666666", "ichliebedich",  "sebastian", "patrick",  "tobias",  "nicole",    "martin",   "bushido",
		"fuckyou",  "trustno1",   "ranger", "buster",        "thomas",    "tigger",   "robert",  "soccer",    "fuck",     "batman",
		"borussia", "passwort1",  "admin",  "administrator", "marketing", "root",     "toor",    "raspberry", "Passw@rd", "administrator",
	};

	extern std::array<std::array<uint8_t, hashing::SHA512_SIZE>, passwd.size()> sha512;

	void fill_sha512();
}