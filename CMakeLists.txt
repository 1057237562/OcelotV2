cmake_minimum_required(VERSION 3.16)
project(Ocelot CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(OCELOT_HEADERS
        include/ocelot/crypto.hpp
        include/ocelot/io.hpp
        include/ocelot/libocelot.hpp
        include/ocelot/logging.hpp
        include/ocelot/protocol.hpp
        include/ocelot/unisocket.hpp)

# Header-only core; the wepoll shim only exists to provide epoll on Windows.
add_library(ocelot INTERFACE)
target_include_directories(ocelot INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(ocelot INTERFACE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
if (WIN32)
    target_sources(ocelot INTERFACE src/wepoll.c)
    target_link_libraries(ocelot INTERFACE wsock32 ws2_32)
endif ()

add_executable(OcelotServer src/serverside.cpp ${OCELOT_HEADERS})
target_link_libraries(OcelotServer PRIVATE ocelot)

add_executable(OcelotClient src/clientside.cpp ${OCELOT_HEADERS})
target_link_libraries(OcelotClient PRIVATE ocelot)

add_executable(HandshakeBench tests/handshake_bench.cpp ${OCELOT_HEADERS})
target_link_libraries(HandshakeBench PRIVATE ocelot)

enable_testing()
add_test(NAME smoke
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke_test.sh $<TARGET_FILE:OcelotServer> $<TARGET_FILE:OcelotClient>)
