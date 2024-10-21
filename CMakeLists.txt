cmake_minimum_required(VERSION 3.29)
project(OcelotV3)

set(CMAKE_CXX_STANDARD 17)

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
        libocelot
        protocol.hpp
        protocol)

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
        libocelot
        protocol.hpp
        protocol)

add_executable(CTest
        io.hpp
        ctest.cpp
        crypto.hpp
        crypto
        unisocket
        unisocket.hpp
        wepoll.c
        wepoll.h
        libocelot.hpp
        libocelot
        protocol.hpp
        protocol)

add_executable(STest
        io.hpp
        stest.cpp
        crypto.hpp
        crypto
        unisocket
        unisocket.hpp
        wepoll.c
        wepoll.h
        libocelot.hpp
        libocelot
        protocol.hpp
        protocol)

find_package(OpenSSL REQUIRED)
if (WIN32)
    target_link_libraries(OcelotServer OpenSSL::SSL OpenSSL::Crypto wsock32 ws2_32)
    target_link_libraries(OcelotClient OpenSSL::SSL OpenSSL::Crypto wsock32 ws2_32)
    target_link_libraries(CTest OpenSSL::SSL OpenSSL::Crypto wsock32 ws2_32)
    target_link_libraries(STest OpenSSL::SSL OpenSSL::Crypto wsock32 ws2_32)
endif ()
