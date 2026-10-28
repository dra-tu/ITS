cmake_minimum_required(VERSION 4.0)
project(TOTP_Prototyp)

set(CMAKE_CXX_STANDARD 20)
#new
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# TOTP-Bibliothek suchen
find_path(OATH_INCLUDE_DIR
        NAMES oath.h
        PATH_SUFFIXES liboath
        PATHS /opt/homebrew/include /usr/local/include
)

find_library(OATH_LIBRARY
        NAMES oath
        PATHS /opt/homebrew/lib /usr/local/lib
)

# Pruefen, ob die Bibliothek gefunden wurde
if(NOT OATH_INCLUDE_DIR OR NOT OATH_LIBRARY)
    message(FATAL_ERROR "TOTP-Bibliothek liboath nicht gefunden!")
endif()

add_executable(TOTP_Prototyp main.cpp)
# TOTP-Bibliothek einbinden
target_include_directories(TOTP_Prototyp PRIVATE
        ${OATH_INCLUDE_DIR}
)

target_link_libraries(TOTP_Prototyp PRIVATE
        ${OATH_LIBRARY}
)