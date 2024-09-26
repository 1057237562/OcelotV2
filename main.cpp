#include "io"
#include "unisocket"
#include <iostream>
#include <memory>
#include <string>

using namespace io;
using namespace std;
using namespace unisocket;

int main() {
    Epoll epoll;
    TcpServer server("0.0.0.0", 3000);
    int cnt = 0;
    while (true) {
        shared_ptr<TcpClient> client = shared_ptr<TcpClient>(server.accept());
        ++cnt;
        shared_ptr<PassiveSocket> passive = make_shared<PassiveSocket>(PassiveSocket());
        passive->read<int>([&](int val, SOCKET socket) {
            cout << val << endl;
            TcpClient sock(socket);
            sock.write(&cnt);
        });
        epoll.registerSocket(client, shared_ptr<PassiveSocket>(passive));
    }
}
