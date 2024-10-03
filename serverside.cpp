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
    vector<Epoll> epoll(cores);
    TcpServer server("0.0.0.0", 2080);
    ocelot::EpollOcelot ocelot(server, {"12345"});
    ocelot.start();
}
