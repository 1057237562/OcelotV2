cmake_minimum_required(VERSION 3.29)
project(OcelotV3)

set(CMAKE_CXX_STANDARD 17)

include_directories(.)

add_executable(OcelotServer crypto.hpp
        serverside.cpp
        crypto
        crypto
        libocelot
        libocelot.hpp
        unisocket
        unisocket.hpp)

find_package(OpenSSL REQUIRED)
if (WIN32)
    target_link_libraries(OcelotServer OpenSSL::SSL OpenSSL::Crypto wsock32 ws2_32)
endif ()