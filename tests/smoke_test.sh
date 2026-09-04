#!/usr/bin/env bash
# End-to-end check: start an origin web server, the Ocelot server and the
# Ocelot client, then push traffic through the tunnel over every supported
# proxy dialect and verify the bytes come back intact.
#
#   tests/smoke_test.sh [path/to/OcelotServer] [path/to/OcelotClient]

set -u

SERVER_BIN="${1:-./build/OcelotServer}"
CLIENT_BIN="${2:-./build/OcelotClient}"

ORIGIN_PORT=18080
UDP_ORIGIN_PORT=18081
OCELOT_PORT=12080
PROXY_PORT=13000

WORK="$(mktemp -d)"
PIDS=()
FAILURES=0

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "  ok   - $1"; }
fail() { echo "  FAIL - $1"; FAILURES=$((FAILURES + 1)); }

check() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then pass "$name"; else
        fail "$name (expected '$expected', got '$actual')"
    fi
}

wait_for_port() {
    local port="$1" tries=100
    while [ $tries -gt 0 ]; do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
        tries=$((tries - 1))
        sleep 0.1
    done
    return 1
}

alive() { kill -0 "$1" 2>/dev/null; }

# ---------------------------------------------------------------- fixtures ---
mkdir -p "$WORK/www"
echo "hello-through-the-tunnel" > "$WORK/www/hello.txt"
head -c 3000000 /dev/urandom > "$WORK/www/big.bin"

( cd "$WORK/www" && exec python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 ) >/dev/null 2>&1 &
PIDS+=($!)
wait_for_port "$ORIGIN_PORT" || { echo "origin server did not start"; exit 1; }

python3 "$(dirname "$0")/udp_echo.py" "$UDP_ORIGIN_PORT" >/dev/null 2>&1 &
PIDS+=($!)

"$SERVER_BIN" --port "$OCELOT_PORT" --cores 2 > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
PIDS+=($SERVER_PID)
wait_for_port "$OCELOT_PORT" || { echo "Ocelot server did not start"; cat "$WORK/server.log"; exit 1; }

"$CLIENT_BIN" --server 127.0.0.1 --server-port "$OCELOT_PORT" --listen "$PROXY_PORT" \
    > "$WORK/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=($CLIENT_PID)
wait_for_port "$PROXY_PORT" || { echo "Ocelot client did not start"; cat "$WORK/client.log"; exit 1; }

echo "running smoke tests"

# ------------------------------------------------------------------- tests ---
check "socks5 by ip" "hello-through-the-tunnel" \
    "$(curl -s --max-time 20 --socks5 127.0.0.1:$PROXY_PORT "http://127.0.0.1:$ORIGIN_PORT/hello.txt")"

check "socks5 by hostname" "hello-through-the-tunnel" \
    "$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:$PROXY_PORT "http://localhost:$ORIGIN_PORT/hello.txt")"

check "socks4" "hello-through-the-tunnel" \
    "$(curl -s --max-time 20 --socks4 127.0.0.1:$PROXY_PORT "http://127.0.0.1:$ORIGIN_PORT/hello.txt")"

check "http connect" "hello-through-the-tunnel" \
    "$(curl -s --max-time 20 -p -x "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/hello.txt")"

# SOCKS5 UDP ASSOCIATE: keep the TCP lifetime connection open, send one UDP
# request through the returned relay endpoint and validate the wrapped reply.
udp_result=$(python3 "$(dirname "$0")/udp_associate_test.py" "$PROXY_PORT" "$UDP_ORIGIN_PORT")
check "socks5 UDP associate" "udp-through-the-tunnel" "$udp_result"

# Large transfer: exercises multi-frame relaying, partial sends and flow control.
curl -s --max-time 60 --socks5 127.0.0.1:$PROXY_PORT \
    "http://127.0.0.1:$ORIGIN_PORT/big.bin" -o "$WORK/big.out"
check "3MB transfer integrity" \
    "$(md5sum < "$WORK/www/big.bin" | cut -d' ' -f1)" \
    "$(md5sum < "$WORK/big.out" | cut -d' ' -f1)"

# Sequential reuse: every request after the first rides the same control link.
seq_ok=0
for _ in $(seq 1 15); do
    [ "$(curl -s --max-time 20 --socks5 127.0.0.1:$PROXY_PORT \
        "http://127.0.0.1:$ORIGIN_PORT/hello.txt")" = "hello-through-the-tunnel" ] \
        && seq_ok=$((seq_ok + 1))
done
check "15 sequential requests" "15" "$seq_ok"

# Concurrent load across both epoll threads.  Only the curls are waited on --
# a bare `wait` would also block on the long-lived server processes.
CURLS=()
for i in $(seq 1 20); do
    curl -s --max-time 30 --socks5 127.0.0.1:$PROXY_PORT \
        "http://127.0.0.1:$ORIGIN_PORT/hello.txt" > "$WORK/c$i.out" &
    CURLS+=($!)
done
for pid in "${CURLS[@]}"; do wait "$pid"; done
conc_ok=$(grep -l "hello-through-the-tunnel" "$WORK"/c*.out 2>/dev/null | wc -l)
check "20 concurrent requests" "20" "$conc_ok"

# An abandoned request must not wedge the proxy: connect, say nothing, hang up.
(exec 3<>/dev/tcp/127.0.0.1/$PROXY_PORT; exec 3>&- 3<&-) 2>/dev/null
printf '\x05\x01\x00' | timeout 2 nc 127.0.0.1 $PROXY_PORT >/dev/null 2>&1
check "survives an abandoned client" "hello-through-the-tunnel" \
    "$(curl -s --max-time 20 --socks5 127.0.0.1:$PROXY_PORT "http://127.0.0.1:$ORIGIN_PORT/hello.txt")"

# A destination that refuses the connection must be reported, not hang, and must
# leave the control link usable.
curl -s --max-time 10 --socks5 127.0.0.1:$PROXY_PORT "http://127.0.0.1:9/x" >/dev/null 2>&1
check "recovers from an unreachable destination" "hello-through-the-tunnel" \
    "$(curl -s --max-time 20 --socks5 127.0.0.1:$PROXY_PORT "http://127.0.0.1:$ORIGIN_PORT/hello.txt")"

alive "$SERVER_PID" && pass "server still running" || fail "server died"
alive "$CLIENT_PID" && pass "client still running" || fail "client died"

# Both processes should be idle now, not spinning on a hung-up socket.
sleep 1
busy=$(ps -o %cpu= -p "$SERVER_PID" "$CLIENT_PID" 2>/dev/null | awk '{ if ($1 > 50.0) c++ } END { print c+0 }')
check "no busy-spinning process" "0" "$busy"

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "all smoke tests passed"
else
    echo "$FAILURES smoke test(s) failed"
    echo "--- server log ---"; tail -40 "$WORK/server.log"
    echo "--- client log ---"; tail -40 "$WORK/client.log"
fi
exit "$FAILURES"
