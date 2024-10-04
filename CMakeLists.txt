cmake_minimum_required(VERSION 3.29)
project(OcelotV3)

set(CMAKE_CXX_STANDARD 20)

include_directories(.)

add_executable(OcelotServer
        io.hpp
        serverside.cpp
        crypto.hpp
        crypto
        unisocket
        unisocket.hpp
        wepoll.c
        wepoll.h
        libocelot.hpp
        libocelot)

add_executable(OcelotClient
        io.hpp
        clientside.cpp
        crypto.hpp
        crypto
        unisocket
        unisocket.hpp
        wepoll.c
        wepoll.h
        libocelot.hpp
        libocelot)

add_executable(OcelotTest
        io.hpp
        test.cpp
        crypto.hpp
        crypto
        unisocket
        unisocket.hpp
        wepoll.c
        wepoll.h
        libocelot.hpp
        libocelot)

find_package(OpenSSL REQUIRED)
if (WIN32)
    target_link_libraries(OcelotServer OpenSSL::SSL OpenSSL::Crypto wsock32 ws2_32)
    target_link_libraries(OcelotClient OpenSSL::SSL OpenSSL::Crypto wsock32 ws2_32)
    target_link_libraries(OcelotTest OpenSSL::SSL OpenSSL::Crypto wsock32 ws2_32)
endif ()
