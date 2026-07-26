# Ocelot

An encrypted SOCKS4 / SOCKS5 / HTTP-CONNECT proxy. A local **client** speaks the
proxy protocol to your application, and tunnels the traffic over AES-256-CBC to a
remote **server**, which opens the real connection to the destination.

```
application ──socks/http──▶ OcelotClient ──encrypted tunnel──▶ OcelotServer ──▶ destination
```

## Layout

```
include/ocelot/
    unisocket.hpp    sockets, non-blocking helpers, DNS cache
    io.hpp           epoll event loop, buffered relay sockets, flow control
    crypto.hpp       AES-CBC / RSA-OAEP / SHA-256 wrappers over OpenSSL
    protocol.hpp     SOCKS4, SOCKS5 and HTTP CONNECT parsing
    libocelot.hpp    tunnel framing, control link, server
    logging.hpp      leveled logging (OCELOT_LOG=0..3)
    wepoll.h         epoll shim for Windows
src/
    serverside.cpp   the relay server
    clientside.cpp   the local proxy
    wepoll.c         (Windows only)
tests/
    smoke_test.sh      end-to-end traffic test over every supported dialect
    handshake_bench.cpp session-setup load test
```

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Requires OpenSSL and a C++17 compiler.

## Run

```sh
# on the remote host
./build/OcelotServer --port 2080 --cores 8 [-cfg ./cfg]

# on your machine
./build/OcelotClient --server <server-ip> --server-port 2080 --listen 3000

curl --socks5 127.0.0.1:3000 https://example.com
```

`--cores` defaults to the number of hardware threads; each core gets its own
epoll thread. Credentials live in `cfg`:

```
2
alice hunter2
bob   correcthorse
```

The first line is the account count, then one `username password` pair per line.
Without a `cfg` file the server falls back to a built-in demo account.

Set `OCELOT_LOG=3` for debug logging (default is warnings and errors only).

## Test

```sh
./tests/smoke_test.sh ./build/OcelotServer ./build/OcelotClient
```

Covers SOCKS5 by IP and by hostname, SOCKS4, HTTP CONNECT, a multi-megabyte
transfer checked byte for byte, sequential and concurrent load, an abandoned
client, and an unreachable destination — then verifies neither process died or
started spinning.

## Wire format

Control link (client → server), one long-lived connection per client:

| opcode      | exchange                                                        |
|-------------|-----------------------------------------------------------------|
| `'O'`       | RSA-1024 key swap, SHA-256 credential check, AES session key    |
| `'O' ^ 1`   | token, `AES(uint32 len)`, `AES(socks5 address)` → `AES(uint32 port)` |

A port of `0` means the request failed. The client then connects to the returned
port and both ends speak the tunnel format:

```
[16] AES(uint32 body_length)
[n ] AES(payload)
```
