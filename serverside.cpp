#include <iostream>
#include <string>
#include "libocelot.hpp"

using namespace io;
using namespace std;
using namespace unisocket;

int cores = 8;

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    cout.tie(nullptr);
    init();
    TcpServer server("0.0.0.0", 2080);
    vector<string> tokens = {crypto::sha256_string("libra\n65536forC")};
    auto ocelot = new ocelot::EpollOcelot(server, tokens);
    ocelot->start();
    delete ocelot;
}
