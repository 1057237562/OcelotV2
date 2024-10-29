#include "io"
#include<bits/stdc++.h>
#include "protocol"
using namespace io;
using namespace std;
using namespace protocol;

Epoll epoll;

void threadApproch(shared_ptr<TcpClient> request, shared_ptr<TcpClient> client) {
    thread th([client,request]() {
        int r;
        char buffer[8192];
        while ((r = client->receive(buffer, 0, 8192)) > 0) {
            request->write(buffer, r);
        }
    });
    if (th.joinable()) th.detach();
    thread th2([client,request]() {
        int r;
        char buffer[8192];
        while ((r = request->receive(buffer, 0, 8192)) > 0) {
            client->write(buffer, r);
        }
    });
    if (th2.joinable()) th2.detach();
}

void epollApproch(shared_ptr<TcpClient> request, shared_ptr<TcpClient> client) {
    auto Ipassive = make_shared<PassiveSocket>();
    auto Opassive = make_shared<PassiveSocket>();
    Ipassive->copyTo(Opassive);
    Opassive->copyTo(Ipassive);
    epoll.registerSocket(request->getFD(), Ipassive);
    epoll.registerSocket(client->getFD(), Opassive);
}

int main() {
    init();
    const TcpServer server("0.0.0.0", 3000);
    while (true) {
        auto request = shared_ptr<TcpClient>(server.accept());
        int version = certificate(request);
        if (version != 5) continue;
        NetworkAddr addr = parseSocks5(interceptSocks5(request));
        cout << "Relaying " << addr.ip << endl << flush;
        if (addr.ip.empty())continue;
        try {
            const auto client = make_shared<TcpClient>(addr.ip, addr.port);
            // threadApproch(request, client);
            epollApproch(request, client);
        } catch (std::runtime_error &e) {
            cerr << e.what() << endl;
        }
    }
    WSACleanup();
}
