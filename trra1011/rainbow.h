#pragma once
#include <cstdint>

#include "hashing.h"

// 1 Gib kann ungefähr 3M einträge halten
// it is smaller now so space for MORE!!!!!!
// 2^(30)÷336 ~= 3.195.660
typedef struct {
    char passwd[hashing::MAX_PASSWD_SIZE];
    uint8_t sha512[hashing::SHA512_SIZE];
} rainbow_entery;

constexpr rainbow_entery rainbow_table[] = {
    {.passwd = "login", .sha512 = {0}},
    {.passwd = "passwort", .sha512 = {0}},
    {.passwd = "123", .sha512 = {0}},
    {.passwd = "123456", .sha512 = {0}},
    {.passwd = "123456789", .sha512 = {0}},
    {.passwd = "password", .sha512={0}},
    {.passwd = "123456", .sha512={0}},
    {.passwd = "12345678", .sha512={0}},
    {.passwd = "1234", .sha512={0}},
    {.passwd = "qwerty", .sha512={0}},
    {.passwd = "12345", .sha512={0}},
    {.passwd = "dragon", .sha512={0}},
    {.passwd = "pussy", .sha512={0}},
    {.passwd = "baseball", .sha512={0}},
    {.passwd = "football", .sha512={0}},
    {.passwd = "letmein", .sha512={0}},
    {.passwd = "monkey", .sha512={0}},
    {.passwd = "696969", .sha512={0}},
    {.passwd = "abc123", .sha512={0}},
    {.passwd = "mustang", .sha512={0}},
    {.passwd = "michael", .sha512={0}},
    {.passwd = "shadow", .sha512={0}},
    {.passwd = "master", .sha512={0}},
    {.passwd = "jennifer", .sha512={0}},
    {.passwd = "111111", .sha512={0}},
    {.passwd = "2000", .sha512={0}},
    {.passwd = "jordan", .sha512={0}},
    {.passwd = "superman", .sha512={0}},
    {.passwd = "harley", .sha512={0}},
    {.passwd = "1234567", .sha512={0}},
    {.passwd = "fuckme", .sha512={0}},
    {.passwd = "hunter", .sha512={0}},
    {.passwd = "fuckyou", .sha512={0}},
    {.passwd = "trustno1", .sha512={0}},
    {.passwd = "ranger", .sha512={0}},
    {.passwd = "buster", .sha512={0}},
    {.passwd = "thomas", .sha512={0}},
    {.passwd = "tigger", .sha512={0}},
    {.passwd = "robert", .sha512={0}},
    {.passwd = "soccer", .sha512={0}},
    {.passwd = "fuck", .sha512={0}},
    {.passwd = "batman", .sha512={0}},
    {.passwd = "test", .sha512={0}},
    {.passwd = "pass", .sha512={0}},
    {.passwd = "killer", .sha512={0}},
    {.passwd = "hockey", .sha512={0}},
    {.passwd = "george", .sha512={0}},
    {.passwd = "charlie", .sha512={0}},
    {.passwd = "andrew", .sha512={0}},
    {.passwd = "michelle", .sha512={0}},
    {.passwd = "love", .sha512={0}},
    {.passwd = "sunshine", .sha512={0}},
    {.passwd = "jessica", .sha512={0}},
    {.passwd = "asshole", .sha512={0}},
    {.passwd = "6969", .sha512={0}},
};

constexpr size_t rainbow_table_len = std::size(rainbow_table);