#ifndef _LIBOCELOT_HPP_
#define _LIBOCELOT_HPP_

#include "crypto"
#include "io"
#include "unisocket"
#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <utility>
#include <vector>
#include "protocol.hpp"

namespace ocelot {
    using namespace std;
    using namespace unisocket;
    using namespace crypto;
    using namespace protocol;
    using namespace io;

    typedef unsigned char byte;

    class PassiveOcelotChannel : public PassiveSocket {
    protected:
        shared_ptr<AES_CBC> aes;
        string buffer;

    public:
        explicit PassiveOcelotChannel(shared_ptr<AES_CBC> aes) : aes(std::move(aes)) {}

        void write(const char *buf, const int len) override {
            buffer.append(buf, len);
            while (!buffer.empty()) {
                string plain(buffer.begin(), buffer.begin() + static_cast<int>(min(buffer.size(), sizeof(AESBlock) - 1)));
                PassiveSocket::write(aes->encrypt(plain).data(), sizeof(AESBlock));
                buffer = buffer.substr(static_cast<int>(min(buffer.size(), sizeof(AESBlock) - 1)));
            }
        }

        void copyTo(const shared_ptr<PassiveSocket> &target) override {
            while (!que.empty())
                que.pop();
            que.emplace(-sizeof(AESBlock), [=](const char *buf, const int len, SOCKET, const shared_ptr<PassiveSocket> &) {
                for (int i = 0; i < len; i += sizeof(AESBlock)) {
                    string encode(buf + i, sizeof(AESBlock));
                    const string decode = aes->decrypt(encode);
                    target->write(decode.data(), static_cast<int>(decode.length()));
                }
            });
            if (rd_buffer.empty()) {
                rd_buffer.resize(MTU);
                ptr = 0;
            }
        }
    };

    class PassiveOcelotControl : public PassiveSocket {
    protected:
        shared_ptr<RSA_PKCS1_OAEP> encryptor = make_shared<RSA_PKCS1_OAEP>();
        shared_ptr<AES_CBC> aes;
        shared_ptr<RSA_PKCS1_OAEP> decrypter;
        shared_ptr<Epoll> allocated_epoll;
        vector<string> &tks;
        map<string, shared_ptr<AES_CBC> > &keys;

    public:
        PassiveOcelotControl(shared_ptr<RSA_PKCS1_OAEP> de, shared_ptr<Epoll> allocate, vector<string> &tokens,
                             map<string, shared_ptr<AES_CBC> > &mp) : decrypter(std::move(de)),
                                                                      allocated_epoll(std::move(allocate)),
                                                                      tks(tokens), keys(mp) {
            read<char>([&](const char op, const SOCKET socket_fd, const shared_ptr<PassiveSocket> &passive_socket) {
                if ((op ^ 'O') == 0) {
                    X509PublicKey pkey(decrypter->getX509PublicKey());
                    passive_socket->write(pkey);

                    passive_socket->read<X509PublicKey>([](X509PublicKey key, SOCKET, const shared_ptr<PassiveSocket> &control) {
                        reinterpret_cast<PassiveOcelotControl *>(control.get())->encryptor->fromX509PublicKey(key);
                    });
                    passive_socket->read<SHA256Digest>([=](const SHA256Digest &digest, const SOCKET socket, shared_ptr<PassiveSocket> control) {
                        int state = 0;
                        string token = string(digest.data, 32);
                        if (binary_search(tks.begin(), tks.end(), token)) {
                            state = 1;
                            passive_socket->write(&state);
                            string key = random_string(32 + 16), iv = key.substr(32, 16);
                            auto ekey = RSABlock(reinterpret_cast<PassiveOcelotControl *>(control.get())->encryptor->
                                encrypt(key));
                            key = key.substr(0, 32);
                            keys[token] = make_shared<AES_CBC>(key, iv);
                            passive_socket->write(ekey);
                        } else {
                            passive_socket->write(&state);
                        }
                    });
                }
                if ((op ^ 'O') == 1) {
                    passive_socket->read<SHA256Digest>([](const SHA256Digest &digest, SOCKET, const shared_ptr<PassiveSocket> &control) {
                        const auto token = string(digest.data, 32);
                        if (reinterpret_cast<PassiveOcelotControl *>(control.get())->keys.find(token) == reinterpret_cast<
                                PassiveOcelotControl *>(control.get())->keys.end()) {
                            return;
                        }
                        auto aes = reinterpret_cast<PassiveOcelotControl *>(control.get())->keys[token];
                        control->read<AESBlock>([aes](const AESBlock &block, const SOCKET, const shared_ptr<PassiveSocket> &control) {
                            string lenstr = aes->decrypt(block);
                            size_t len;
                            memcpy(&len, lenstr.c_str(), sizeof(size_t));
                            control->read(static_cast<int>(len), [len,aes](const char *response, SOCKET, const shared_ptr<PassiveSocket> &control) {
                                string socks = string(response, len);
                                NetworkAddr addr = parseSocks5(aes->decrypt(socks));
                                const TcpServer transmit("0.0.0.0", 0);
                                int port_num = transmit.getPort();
                                string port((char *) &port_num, 4);
                                auto aes_block = AESBlock(aes->encrypt(port));
                                control->write(aes_block);
                                auto server = make_shared<PassiveServer>(
                                    [control,aes,addr](const shared_ptr<TcpClient> &request, const shared_ptr<PassiveSocket> &) {
                                        cout << "Connection inbound for " << addr.ip << ":" << addr.port << endl << flush;
                                        try {
                                            const auto target = make_shared<TcpClient>(addr.ip, addr.port);
                                            const auto passive = make_shared<PassiveSocket>();
                                            const auto channel = make_shared<PassiveOcelotChannel>(aes);
                                            passive->copyTo(channel);
                                            channel->copyTo(passive);
                                            reinterpret_cast<PassiveOcelotControl *>(control.get())->allocated_epoll->registerSocket(request->getFD(), channel);
                                            reinterpret_cast<PassiveOcelotControl *>(control.get())->allocated_epoll->registerSocket(target->getFD(), passive);
                                        } catch (runtime_error &e) {
                                            cout << e.what() << endl << flush;
                                        }
                                    }, true);
                                reinterpret_cast<PassiveOcelotControl *>(control.get())->allocated_epoll->registerSocket(transmit.getFD(), server);
                            });
                        });
                    });
                }
            });
        }
    };

    class EpollOcelot {
        Epoll epoll;
        TcpServer server;
        vector<string> tokens;
        shared_ptr<RSA_PKCS1_OAEP> de = make_shared<RSA_PKCS1_OAEP>();
        map<string, shared_ptr<AES_CBC> > keys;
        vector<shared_ptr<Epoll> > bucket;
        bool closed = false;

    public:
        EpollOcelot(const TcpServer &server, vector<string> tks,
                    int core = 1) : server(server), tokens(std::move(tks)) {
            de->generateKey();
            sort(tokens.begin(), tokens.end());
            bucket.resize(core, make_shared<Epoll>());
        }

        ~EpollOcelot() { closed = true; }

        void start() {
            int i = 0;
            while (!closed) {
                auto client = shared_ptr<TcpClient>(server.accept());
                client->setRecvTimeout(5);
                client->setSendTimeout(5);
                epoll.registerSocket(
                    client->getFD(), make_shared<PassiveOcelotControl>(de, bucket[i], tokens, keys));
                i = (i + 1) % bucket.size();
            }
        }
    };

    class OcelotChannel : public NetworkStream {
    protected:
        TcpClient *socket;
        AES_CBC *aes;

    public:
        OcelotChannel(TcpClient *client, AES_CBC *aes)
            : socket(client)
              , aes(aes) {}

        void write(std::string &str) {
            int len = str.length();
            string slen = string((char *) &len, 4);
            slen = aes->encrypt(slen);
            socket->write(slen, sizeof(AESBlock));
            socket->write(str, len);
        }

        bool read(std::string &str) {
            byte header[sizeof(AESBlock)];
            if (!socket->read(&header))
                return false;
            string slen = string((char *) header, sizeof(AESBlock));
            slen = aes->decrypt(slen);
            int len;
            memcpy(&len, slen.data(), 4);
            std::string buf;
            if (!socket->read(buf, len))
                return false;
            str = aes->decrypt(buf);
            return true;
        }

        bool isClosed() override {
            return socket->isClosed();
        }
    };

    class OcelotClient {
    protected:
        TcpClient *socket;
        string usertoken;
        AES_CBC aes;

    public:
        OcelotClient(TcpClient *client, const string &user, const string &password)
            : socket(client)
              , usertoken(user + "\n" + password) {}

        void handshake() {
            socket->write(&"");
            string key, iv;
            socket->read(key);
            RSA_PKCS1_OAEP en;
            en.fromX509PublicKey(key);

            RSA_PKCS1_OAEP de;
            de.generateKey();
            string pkey = de.getX509PublicKey();
            socket->read(pkey);

            string token = en.encrypt(usertoken);
            socket->write(token);

            string response;
            socket->read(response);
            key = de.decrypt(response);
            socket->read(response);
            iv = de.decrypt(response);
            aes = AES_CBC(key, iv);
        }
    };
}

#endif
