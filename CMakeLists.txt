cmake_minimum_required(VERSION 4.3)
project(ITS)

set(CMAKE_CXX_STANDARD 23)

add_subdirectory(trra1011)

add_executable(email_demo email_recovery_demo.cpp)