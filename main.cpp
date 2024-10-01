#include "io"
#include "unisocket"
#include <iostream>
#include <memory>
#include <string>

using namespace io;
using namespace std;
using namespace unisocket;

int main() {
    init();
    Epoll epoll;
    TcpServer server("0.0.0.0", 2080);
    atomic_int cnt(0);
    while (true) {
        cout << "Waiting for connection..." << endl;
        shared_ptr<TcpClient> client = shared_ptr<TcpClient>(server.accept());
        cout << "Connection established!" << endl;
        shared_ptr<PassiveSocket> passive = make_shared<PassiveSocket>(PassiveSocket());
        passive->read<int>([&](int val, SOCKET socket) {
            cout << val << endl;
            TcpClient sock(socket);
            ++cnt;
            sock.write(&cnt);
        });
        epoll.registerSocket(client, shared_ptr<PassiveSocket>(passive));
    }
}
