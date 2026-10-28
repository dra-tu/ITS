#pragma once

#include "hashing.h"

namespace rainbow {
	// reverence:
	// https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt
	// https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/Language-Specific/German_Pwdb_common-password-list-top-150.txt
	// https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt
	constexpr std::array passwd{
		"login",    "passwort",   "123",      "123456",        "123456789", "password",   "1234567",  "345678",    "1234",      "qwerty",
		"12345",    "dragon",     "pussy",    "baseball",      "football",  "letmein",    "monkey",   "696969",    "abc123",    "mustang",
		"shadow",   "master",     "jennifer", "111111",        "2000",      "jordan",     "superman", "harley",    "1234567",   "fuckme",
		"fuckyou",  "trustno1",   "ranger",   "buster",        "thomas",    "tigger",     "robert",   "soccer",    "fuck",      "batman",
		"killer",   "hockey",     "george",   "charlie",       "andrew",    "michelle",   "love",     "sunshine",  "jessica",   "asshole",
		"michael",  "hunter",     "test",     "pass",          "6969",      "schalke",    "michael",  "starwars",  "computer",  "werder",
		"abc123",   "wasser",     "andreas",  "florian",       "internet",  "michelle",   "sommer",   "berlin",    "000000",    "asdfgh",
		"sandra",   "pokemon",    "marcel",   "Passwort",      "thomas",    "hamburg",    "dragon",   "christian", "bayern",    "geheim",
		"handball", "dortmund",   "666666",   "ichliebedich",  "sebastian", "patrick",    "tobias",   "nicole",    "martin",    "bushido",
		"sascha",   "stefan",     "asdasd",   "fabian",        "dominik",   "1q2w3e4r5t", "jasmin",   "justin",    "logitech",  "eminem",
		"benjamin", "maximilian", "sabrina",  "yxcvbnm",       "samsung",   "SKIFFY",     "1234qwer", "markus",    "schule",    "hallo1",
		"pascal",   "merlin",     "nadine",   "1234567891",    "1qay2wsx",  "snoopy",     "moritz",   "medion",    "lollol",    "playboy",
		"123qwe",   "vanessa",    "mercedes", "matrix",        "philipp",   "oliver",     "wertz123", "sunshine",  "hurensohn", "Hallo123",
		"borussia", "passwort1",  "admin",    "administrator", "marketing", "root",       "toor",     "raspberry", "Passw@rd",  "administrator",
	};

	extern std::array<std::array<uint8_t, hashing::SHA512_SIZE>, passwd.size()> sha512;

	void fill_sha512();
}