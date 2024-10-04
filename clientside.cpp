#include "crypto"
#include "unisocket"
#include <iostream>
#include <string>

#include "libocelot.hpp"

int main() {
    using namespace unisocket;
    using namespace std;
    using namespace crypto;
    init();

    SHA256Digest usertoken = SHA256Digest(sha256_string("libra\n65536forC"));
    TcpClient client = TcpClient("127.0.0.1", 2080);
    char op = 'O';
    client.write(op);
    X509PublicKey pkey;
    client.read(pkey);
    RSA_PKCS1_OAEP en;
    en.fromX509PublicKey(pkey);

    RSA_PKCS1_OAEP de;
    de.generateKey();
    pkey = X509PublicKey(de.getX509PublicKey());
    client.write(pkey);

    client.write(usertoken);

    string response;
    response.resize(128);
    client.read(response, 128);
    string key = de.decrypt(response);
    string iv = key.substr(32, 16);
    key = key.substr(0, 32);
    AES_CBC aes(key, iv);
    cout << key << endl << iv << endl;

    client.close();
}
