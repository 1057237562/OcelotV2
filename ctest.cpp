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
    while (true) {
        vector<thread> threads;
        for (int i = 0; i < 10000; i++) {
            threads.emplace_back([&](const int, const shared_ptr<TcpClient> client) {
                try {
                    crypto::SHA256Digest usertoken = crypto::SHA256Digest(crypto::sha256_string("libra\n65536forC"));
                    char op = 'O';
                    client->write(op);
                    crypto::X509PublicKey pkey;
                    client->read(pkey);
                    crypto::RSA_PKCS1_OAEP en;
                    en.fromX509PublicKey(pkey);

                    crypto::RSA_PKCS1_OAEP de;
                    de.generateKey();
                    pkey = crypto::X509PublicKey(de.getX509PublicKey());
                    client->write(pkey);
                    // cout << "RSA Exchanged completed" << endl;

                    client->write(usertoken);
                    int state = 0;
                    client->read(state);
                    if (state) {
                        string response;
                        response.resize(128);
                        client->read(response, 128);
                        string key = de.decrypt(response);
                        string iv = key.substr(32, 16);
                        key = key.substr(0, 32);
                        crypto::AES_CBC aes(key, iv);
                        // cout << "AES Exchanged completed" << endl;
                    } else {
                        cerr << "Certification failed" << endl;
                    }
                    // cout << key << endl << iv << endl;

                    client->close();
                } catch (runtime_error &e) {
                    cerr << e.what() << endl;
                }
            }, i, make_shared<TcpClient>("127.0.0.1", 2080));
        }
        for (int i = 0; i < 10000; i++) {
            if (threads[i].joinable()) {
                threads[i].join();
                cout << "Thread " << i << " finished" << endl;
            }
        }
    }
    WSACleanup();
}
