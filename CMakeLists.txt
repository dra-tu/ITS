cmake_minimum_required(VERSION 4.3)
project(ITS)

set(CMAKE_CXX_STANDARD 23)

find_package(OpenSSL REQUIRED Crypto)
find_package(SQLite3)

add_executable(cli main.cpp
        hashing.cpp
        hashing.h)
target_link_libraries(cli PRIVATE OpenSSL::Crypto)
target_compile_definitions(cli PRIVATE OPENSSL_NO_DEPRECATED)
target_link_libraries(cli PRIVATE SQLite3::SQLite3)

add_executable(example exampl.cpp)
target_link_libraries(example  PRIVATE OpenSSL::Crypto)
