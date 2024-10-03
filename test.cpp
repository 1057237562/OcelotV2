#include "io"
#include "unisocket"
#include <iostream>
#include <memory>
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
    int val = 0;
    while (true) {
        cout << "Waiting for connection..." << endl;
        shared_ptr<TcpClient> client = shared_ptr<TcpClient>(server.accept());
        cout << "Connection established!" << endl;
        shared_ptr<PassiveSocket> passive = make_shared<PassiveSocket>(PassiveSocket());
        passive->copyTo(client);
        epoll[val++ % cores].registerSocket(client, passive);
    }
}
