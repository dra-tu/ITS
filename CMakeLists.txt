cmake_minimum_required(VERSION 4.3)
project(ITS)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(passwd_store_and_attack)

add_executable(email_demo email_recovery_demo.cpp)