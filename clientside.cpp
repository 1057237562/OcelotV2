#include "crypto"
#include "unisocket"
#include <iostream>
#include <string>

#include "libocelot.hpp"

int main(void) {
    using namespace unisocket;
    using namespace std;
    using namespace crypto;
    string usertoken = sha256_string("libra\n65536forC");

    init();
    TcpClient client = TcpClient("127.0.0.1", 2080);
    char op = 0;
    client.write(op);
    X509PublicKey key{};
    client.read(&key);
    RSA_PKCS1_OAEP en;
    en.fromX509PublicKey(key);

    RSA_PKCS1_OAEP de;
    de.generateKey();
    string pkey = de.getX509PublicKey();
    client.write(pkey);

    string token = en.encrypt(usertoken);
    client.write(token);

    string response;
    client.read(response);
    key = de.decrypt(response);
    client.read(response);
    iv = de.decrypt(response);
    AES_CBC aes(key, iv);
    cout << key << ":" << iv << endl;

    client.close();
}
