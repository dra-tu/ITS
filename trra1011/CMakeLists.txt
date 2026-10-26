find_package(OpenSSL REQUIRED Crypto)
find_package(SQLite3)

add_executable(cli main.cpp
        hashing.cpp
        hashing.h
        db.cpp
        db.h)
target_compile_options(cli PRIVATE -Wall -Wextra -Wconversion -Wsign-conversion -pedantic-errors)
target_compile_definitions(cli PRIVATE OPENSSL_NO_DEPRECATED)
target_link_libraries(cli PRIVATE OpenSSL::Crypto)
target_link_libraries(cli PRIVATE SQLite3::SQLite3)
