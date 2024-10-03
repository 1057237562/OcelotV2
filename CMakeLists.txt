cmake_minimum_required(VERSION 3.29)
project(OcelotV3)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(OcelotServer
        io.hpp
        serverside.cpp
        crypt.hpp
        crypt
        unisocket
        unisocket.hpp
        wepoll.c
        wepoll.h
        libocelot.hpp
        libocelot)

add_executable(OcelotTest
        io.hpp
        test.cpp
        unisocket
        unisocket.hpp
        wepoll.c
        wepoll.h)

target_link_libraries(OcelotServer ssl crypto)
if (WIN32)
    target_link_libraries(OcelotServer wsock32 ws2_32)
    target_link_libraries(OcelotTest wsock32 ws2_32)
endif ()
