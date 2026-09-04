#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# ---------- install dependencies ----------
install_deps() {
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq cmake g++ libssl-dev
    elif command -v dnf &>/dev/null; then
        dnf install -y cmake gcc-c++ openssl-devel
    elif command -v yum &>/dev/null; then
        yum install -y cmake gcc-c++ openssl-devel
    elif command -v apk &>/dev/null; then
        apk add --no-cache cmake g++ openssl-dev
    else
        echo "unknown package manager — install cmake, g++, openssl-devel manually"
    fi
}

# install deps
install_deps

# ---------- build ----------
BUILD_DIR="build"
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" -j"$(nproc)"

# ---------- create credential file ----------
cat > cfg <<'EOF'
1
libra 65536forC
EOF

echo ""
echo "===== Done ====="
echo "Server:  $BUILD_DIR/OcelotServer  --port <port>"
echo "Client:  $BUILD_DIR/OcelotClient  --server <ip> --server-port <port> --listen <port>"
echo ""
echo "Example:"
echo "  $BUILD_DIR/OcelotServer --port 3060"
echo "  $BUILD_DIR/OcelotClient --server 127.0.0.1 --server-port 3060 --listen 3000"
