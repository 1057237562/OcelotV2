#include "io"
#include<bits/stdc++.h>
#include "protocol"
using namespace io;
using namespace std;
using namespace protocol;

Epoll epoll;

int main() {
    init();
    TcpServer server("0.0.0.0", 3000);
    while (true) {
        auto request = shared_ptr<TcpClient>(server.accept());
        int version = certificate(request);
        if (version != 5) continue;
        NetworkAddr addr = parseSocks5(interceptSocks5(request));
        cout << "Relaying " << addr.ip << endl << flush;
        if (addr.ip.empty())continue;
        try {
            auto client = make_shared<TcpClient>(addr.ip, addr.port);
            auto Ipassive = make_shared<PassiveSocket>();
            auto Opassive = make_shared<PassiveSocket>();
            Ipassive->copyTo(Opassive);
            Opassive->copyTo(Ipassive);
            epoll.registerSocket(request->getFD(), Ipassive);
            epoll.registerSocket(client->getFD(), Opassive);
        } catch (std::runtime_error &e) {
            cerr << e.what() << endl;
        }
    }
    WSACleanup();
}
