find_package(OpenSSL REQUIRED Crypto)
find_package(SQLite3)

add_executable(cli main.cpp
        hashing.cpp
        hashing.h
        db.cpp
        db.h
        rainbow.h)
target_compile_options(cli PRIVATE -Wall -Wextra -Wconversion -Wsign-conversion -pedantic-errors)
target_compile_definitions(cli PRIVATE OPENSSL_NO_DEPRECATED)
target_link_libraries(cli PRIVATE OpenSSL::Crypto)
target_link_libraries(cli PRIVATE SQLite3::SQLite3)
# BEGINN TOTP-ERGAENZUNG
find_path(OATH_INCLUDE_DIR
        NAMES oath.h
        PATHS /opt/homebrew/include /usr/local/include
        PATH_SUFFIXES liboath
)

find_library(OATH_LIBRARY
        NAMES oath
        PATHS /opt/homebrew/lib /usr/local/lib
)

if(NOT OATH_INCLUDE_DIR OR NOT OATH_LIBRARY)
    message(FATAL_ERROR
            "Liboath fehlt. Bitte oath-toolkit installieren."
    )
endif()

target_include_directories(cli PRIVATE ${OATH_INCLUDE_DIR})
target_link_libraries(cli PRIVATE ${OATH_LIBRARY})
# ENDE TOTP-ERGAENZUNG
