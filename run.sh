#!/usr/bin/env bash
# Rebuild and restart the Ocelot server managed by systemd.
set -euo pipefail

cd "$(dirname "$0")"

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)" --target OcelotServer

systemctl stop ocelot || true
install -m 755 build/OcelotServer ./serverside
systemctl start ocelot

# Sanitizer build:
#   cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
#         -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g"
