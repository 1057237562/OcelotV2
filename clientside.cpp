#include <iostream>
#include <string>
#include "protocol"
#include "libocelot"

using namespace std;
using namespace unisocket;
using namespace crypto;
using namespace protocol;
using namespace io;

const string ip = "127.0.0.1";

const SHA256Digest userToken = SHA256Digest(sha256_string("libra\n65536forC"));

RSA_PKCS1_OAEP en;
RSA_PKCS1_OAEP de;
shared_ptr<AES_CBC> aes;

void handshake(TcpClient &client) {
    char op = 'O';
    client.write(op);
    X509PublicKey pkey;
    client.read(pkey);
    en.fromX509PublicKey(pkey);

    de.generateKey();
    pkey = X509PublicKey(de.getX509PublicKey());
    client.write(pkey);

    client.write(userToken);
    int state = 0;
    client.read(state);
    if (state) {
        RSABlock rsa_block;
        client.read<RSABlock>(rsa_block);
        string response(rsa_block.data, 128);
        string key = de.decrypt(response);
        string iv = key.substr(32, 16);
        key = key.substr(0, 32);
        aes = make_shared<AES_CBC>(key, iv);
    } else {
        cerr << "Certification failed" << endl;
    }
    cout << "Handshake complete" << endl << flush;
}

TcpClient *openConnection(TcpClient &controlLink, string &addr) {
    char op = 'O' ^ 1;
    controlLink.write(op);
    controlLink.write(userToken);
    size_t addrLength = addr.length();
    string addrCipher(reinterpret_cast<char *>(&addrLength), sizeof(size_t));
    AESBlock len(aes->encrypt(addrCipher));
    controlLink.write(len);
    controlLink.write(addr, addrLength);
    AESBlock block;
    controlLink.read<AESBlock>(block);
    string portStr = aes->decrypt(block);
    int port;
    memcpy(&port, portStr.data(), portStr.size());
    cout << "Relaying to port num : " << port << endl << flush;
    return new TcpClient(ip, port);
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    cout.tie(nullptr);
    init();
    auto client = TcpClient(ip, 2080);
    handshake(client);
    client.close();
    const auto server = TcpServer("0.0.0.0", 3000);
    shared_ptr<Epoll> epoll = make_shared<Epoll>();
    while (true) {
        auto request = shared_ptr<TcpClient>(server.accept());
        string response;
        switch (certificate(request)) {
            case 5:
                response = interceptSocks5(request);
                break;
            case 4:
                response.resize(6);
                request->read(response, 6);
                response = socks4To5(response);
                break;
            case 1:
                response.resize(8192);
                int n = request->receive(response.data(), 0, 8192);
                while (response[n - 1] != 0x0A || response[n - 3] != 0x0A) {
                    n += request->receive(response.data(), n, 8192 - n);
                }
                request->write(httpSucceed, httpSucceed.length());
                break;
        }
        if (response.empty()) {
            request->close();
            continue;
        }
        string cipher = aes->encrypt(response);

        auto controlLink = TcpClient(ip, 2080);
        const auto conn = shared_ptr<TcpClient>(openConnection(controlLink, cipher));
        auto passive = make_shared<PassiveSocket>();
        auto channel = make_shared<ocelot::PassiveOcelotChannel>(aes);
        passive->copyTo(channel);
        channel->copyTo(passive);
        epoll->registerSocket(request->getFD(), passive);
        epoll->registerSocket(conn->getFD(), channel);
        controlLink.close();
    }
}
