#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "ocelot/libocelot.hpp"
#include "ocelot/logging.hpp"

using namespace std;
using namespace unisocket;

namespace {
    /// Reads `count` then `count` username/password pairs, one per line.
    /// Falls back to the built-in demo account when there is no config file.
    vector<string> loadTokens(const string &path) {
        vector<string> tokens;
        ifstream config(path);
        if (!config) {
            LOG_WARN("no credential file at %s, using the built-in demo account", path.c_str());
            return {crypto::sha256_string("libra\n65536forC")};
        }
        int count = 0;
        config >> count;
        for (int i = 0; i < count; i++) {
            string username, password;
            if (!(config >> username >> password))
                break;
            tokens.push_back(crypto::sha256_string(username + "\n" + password));
        }
        if (tokens.empty()) {
            LOG_ERROR("%s did not contain any usable credentials", path.c_str());
            exit(1);
        }
        return tokens;
    }
}

int main(const int argc, char **argv) {
    int port = 2080;
    int cores = static_cast<int>(thread::hardware_concurrency());
    string cfg = "./cfg";

    for (int i = 1; i < argc; i++) {
        const string arg = argv[i];
        if (arg == "--port" && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (arg == "--cores" && i + 1 < argc)
            cores = atoi(argv[++i]);
        else if (arg == "-cfg" && i + 1 < argc)
            cfg = argv[++i];
        else {
            fprintf(stderr, "usage: %s [--port N] [--cores N] [-cfg PATH]\n", argv[0]);
            return 1;
        }
    }
    if (cores < 1)
        cores = 1;

    init();
    const TcpServer server("0.0.0.0", port);
    // Each core gets its own epoll thread now; the old code handed the same
    // shared_ptr to every bucket, so all relays shared a single thread.
    ocelot::EpollOcelot ocelot(server, loadTokens(cfg), cores);
    LOG_INFO("Ocelot server listening on port %d across %d epoll threads", port, cores);
    printf("Ocelot server listening on port %d across %d epoll threads\n", port, cores);
    fflush(stdout);
    ocelot.start();
}
