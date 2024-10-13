#include "crypto"
#include "unisocket"
#include <iostream>
#include <string>

#include "libocelot.hpp"

using namespace std;
using namespace unisocket;
using namespace crypto;

const string ip = "127.0.0.1";

const SHA256Digest userToken = SHA256Digest(sha256_string("libra\n65536forC"));

RSA_PKCS1_OAEP en;
RSA_PKCS1_OAEP de;
AES_CBC aes;

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
        aes = AES_CBC(key, iv);
        cout << key << endl << iv << endl;
    } else {
        cerr << "Certification failed" << endl;
    }
}

TcpClient *openConnection(TcpClient &controlLink) {
    char op = 'O' ^ 1;
    controlLink.write(op);
    controlLink.write(userToken);
    AESBlock block;
    controlLink.read<AESBlock>(block);
    string cipher = string(block.data, 16);
    string portStr = aes.decrypt(cipher);
    int port;
    memcpy(&port, portStr.data(), portStr.size());
    cout << "Relaying to port num : " << port << endl;
    return new TcpClient(ip, port);
}

int main() {
    init();
    auto client = TcpClient(ip, 2080);
    handshake(client);
    client.close();
    auto controlLink = TcpClient(ip, 2080);
    auto conn = shared_ptr<TcpClient>(openConnection(controlLink));
    conn->close();
    controlLink.close();
}
