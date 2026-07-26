// Hammers the server's control-link handshake to check that it stays healthy
// and to time how long a session setup takes.
//
//   HandshakeBench [--host IP] [--port N] [--count N] [--concurrency N]

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "ocelot/crypto.hpp"
#include "ocelot/unisocket.hpp"

using namespace std;
using namespace unisocket;
using namespace crypto;

namespace {
    string host = "127.0.0.1";
    int port = 2080;
    int total = 200;
    int concurrency = 16;

    atomic_int succeeded{0};
    atomic_int failed{0};

    bool oneHandshake() {
        try {
            TcpClient client(host, port);
            const auto token = SHA256Digest(sha256_string("libra\n65536forC"));

            if (!client.write('O'))
                return false;

            X509PublicKey pkey;
            if (!client.read(pkey))
                return false;
            RSA_PKCS1_OAEP en;
            en.fromX509PublicKey(pkey);

            RSA_PKCS1_OAEP de;
            de.generateKey();
            if (!client.write(X509PublicKey(de.getX509PublicKey())))
                return false;
            if (!client.write(token))
                return false;

            int state = 0;
            if (!client.read(state) || !state)
                return false;

            RSABlock block;
            if (!client.read<RSABlock>(block))
                return false;
            const string material = de.decrypt(string(block.data, sizeof(block.data)));
            return material.size() >= 48;
        } catch (const runtime_error &e) {
            fprintf(stderr, "handshake failed: %s\n", e.what());
            return false;
        }
    }
}

int main(const int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const string arg = argv[i];
        if (arg == "--host" && i + 1 < argc)
            host = argv[++i];
        else if (arg == "--port" && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (arg == "--count" && i + 1 < argc)
            total = atoi(argv[++i]);
        else if (arg == "--concurrency" && i + 1 < argc)
            concurrency = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s [--host IP] [--port N] [--count N] [--concurrency N]\n", argv[0]);
            return 1;
        }
    }
    if (concurrency < 1)
        concurrency = 1;

    init();
    atomic_int remaining{total};
    const auto started = chrono::steady_clock::now();

    // Bounded concurrency; the original spawned 10000 threads in a loop, which
    // measured the scheduler more than it measured the server.
    vector<thread> workers;
    workers.reserve(concurrency);
    for (int i = 0; i < concurrency; i++) {
        workers.emplace_back([&] {
            while (remaining.fetch_sub(1) > 0) {
                if (oneHandshake())
                    ++succeeded;
                else
                    ++failed;
            }
        });
    }
    for (auto &w: workers)
        w.join();

    const auto elapsed = chrono::duration<double>(chrono::steady_clock::now() - started).count();
    printf("%d ok, %d failed in %.2fs (%.1f handshakes/s)\n",
           succeeded.load(), failed.load(), elapsed, succeeded.load() / (elapsed > 0 ? elapsed : 1));
    return failed.load() ? 1 : 0;
}
