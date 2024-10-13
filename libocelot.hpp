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

namespace socks {
    using namespace std;

    struct NetworkAddr {
        string ip;
        int port;
    };
}

namespace ocelot {
    using namespace std;
    using namespace unisocket;
    using namespace crypto;
    using namespace socks;
    using namespace io;

    typedef unsigned char byte;

    inline NetworkAddr parseAddr(string buffer) {
        // This is Socks5
        NetworkAddr res = {"", -1};
        if (buffer.empty())
            return res;
        switch (buffer[3]) {
            case 0x01:
                buffer = buffer.substr(4);
                res.ip = to_string((byte) buffer[0]) + "." + to_string((byte) buffer[1]) + "." +
                         to_string((byte) buffer[2]) + "." + to_string((byte) buffer[3]);
                buffer = buffer.substr(4);
                break;
            case 0x03:
                buffer = buffer.substr(4);
                byte len;
                memcpy(&len, buffer.data(), 1);
                buffer = buffer.substr(1);
                res.ip = buffer.substr(0, len);
                buffer = buffer.substr(len);
                break;
            case 0x04:
                buffer = buffer.substr(4);
            // not support IPV6 for now
            // res.ip = "[" + buffer.substr(0, 4) + ":" + buffer.substr(4, 4) + ":" + buffer.substr(8, 4) + ":" + buffer.substr(12, 4) + "]";
                buffer = buffer.substr(16);
                break;
            default: cerr << "Invalid network address format" << endl;
        }
        res.port = static_cast<int>(static_cast<byte>(buffer[0])) << 8 | static_cast<int>(static_cast<byte>(buffer[1]));
        return res;
    }

    class PassiveOcelotChannel : public PassiveSocket {
    protected:
        shared_ptr<AES_CBC> aes;
        NetworkAddr addr;
        string buffer;

    public:
        explicit PassiveOcelotChannel(shared_ptr<AES_CBC> aes, NetworkAddr addr) : aes(std::move(aes)),
            addr(std::move(addr)) {}

        void write(const char *buf, const int len) override {
            buffer.append(buf, len);
            while (buffer.size() >= 128) {
                string plain = buffer.substr(0, 128);
                wr_buffer.append(aes->encrypt(plain));
                buffer = buffer.substr(128);
            }
        }

        void copyTo(const shared_ptr<PassiveSocket> &target) override {
            while (!que.empty())
                que.pop();
            que.emplace(-128, [=](const char *buf, const int len, SOCKET, PassiveSocket *) {
                string encode(buf, len);
                string decode = aes->decrypt(encode);
                target->write(decode.c_str(), static_cast<int>(decode.length()));
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
            read<char>([&](const char op, const SOCKET socket_fd, PassiveSocket *passive_socket) {
                if ((op ^ 'O') == 0) {
                    X509PublicKey pkey(decrypter->getX509PublicKey());
                    passive_socket->write(pkey);

                    passive_socket->read<X509PublicKey>([](X509PublicKey key, SOCKET, PassiveSocket *control) {
                        reinterpret_cast<PassiveOcelotControl *>(control)->encryptor->fromX509PublicKey(key);
                    });
                    passive_socket->read<SHA256Digest>(
                        [=](const SHA256Digest &digest, const SOCKET socket, PassiveSocket *control) {
                            int state = 0;
                            string token = string(digest.data, 32);
                            if (binary_search(tks.begin(), tks.end(), token)) {
                                state = 1;
                                passive_socket->write(&state);
                                string key = random_string(32 + 16), iv = key.substr(32, 16);
                                auto ekey = AESBlock(reinterpret_cast<PassiveOcelotControl *>(control)->encryptor->
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
                    passive_socket->read<SHA256Digest>(
                        [&](const SHA256Digest &digest, const SOCKET socket, PassiveSocket *control) {
                            if (keys.find(digest.data) == keys.end()) {
                                return;
                            }
                            TcpClient outbound(socket);
                            TcpServer transmit("0.0.0.0", 0);
                            int port_num = transmit.getPort();
                            string port((char *) &port_num, 4);
                            const auto aes = keys[digest.data];
                            auto aes_block = AESBlock(aes->encrypt(port));
                            outbound.write(aes_block);
                            const auto request = shared_ptr<TcpClient>(transmit.accept(5));
                            transmit.close();
                            if (request != nullptr) {
                                return;
                            }
                            passive_socket->read<AESBlock>(
                                [request,aes](const AESBlock &block, SOCKET, PassiveSocket *control) {
                                    string block_str(block.data);
                                    NetworkAddr addr = parseAddr(aes->decrypt(block_str));
                                    shared_ptr<TcpClient> target = make_shared<TcpClient>(addr.ip, addr.port);
                                    auto passive = make_shared<PassiveSocket>();
                                    auto channel = make_shared<PassiveOcelotChannel>(aes, addr);
                                    reinterpret_cast<PassiveOcelotControl *>(control)->allocated_epoll->registerSocket(
                                        request, channel);
                                    reinterpret_cast<PassiveOcelotControl *>(control)->allocated_epoll->registerSocket(
                                        target, passive);
                                    passive->copyTo(channel);
                                    channel->copyTo(passive);
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
                    client, make_shared<PassiveOcelotControl>(de, bucket[i], tokens, keys));
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
            socket->write(slen, 16);
            socket->write(str, len);
        }

        bool read(std::string &str) {
            byte header[16];
            if (!socket->read(&header))
                return false;
            string slen = string((char *) header, 16);
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
        OcelotClient(TcpClient *client, string user, string password)
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

    // class OcelotServer {
    // protected:
    //     struct Session {
    //         RSA_PKCS1_OAEP rsa;
    //         AES_CBC aes;
    //     };
    //
    //     TcpServer server;
    //     vector<string> tokens;
    //     map<string, Session> sessions;
    //     RSA_PKCS1_OAEP de;
    //
    // public:
    //     OcelotServer(const TcpServer &server, vector<string> tks)
    //         : server(server)
    //           , tokens(std::move(tks)) {
    //         de.generateKey();
    //         sort(this->tokens.begin(), this->tokens.end());
    //     }
    //
    //     void start() {
    //         while (true) {
    //             auto client = shared_ptr<TcpClient>(server.accept());
    //             client->setRecvTimeout(5);
    //             client->setSendTimeout(5);
    //             try {
    //                 char op;
    //                 if (!client->read(&op)) {
    //                     client->close();
    //                     continue;
    //                 }
    //                 if (!op) {
    //                     string pkey = de.getX509PublicKey();
    //                     if (!client->write(pkey)) {
    //                         client->close();
    //                         return;
    //                     }
    //
    //                     string key, iv;
    //                     RSA_PKCS1_OAEP en;
    //                     if (!client->read(pkey)) {
    //                         client->close();
    //                         return;
    //                     }
    //                     en.fromX509PublicKey(pkey);
    //
    //                     string token;
    //                     if (!client->read(token)) {
    //                         client->close();
    //                         return;
    //                     }
    //                     token = de.decrypt(token);
    //                     token = token.substr(0, strlen(token.data()));
    //                     key = random_string(32 + 16), iv = key.substr(32, 16);
    //                     key = key.substr(0, 32);
    //                     AES_CBC aes(key, iv);
    //                     string ekey = en.encrypt(key);
    //                     string eiv = en.encrypt(iv);
    //                     if (binary_search(tokens.begin(), tokens.end(), token)) {
    //                         sessions[token] = {en, aes};
    //                         cout << "Session established with" << endl
    //                                 << token << endl;
    //                         if (!client->write(ekey)) {
    //                             client->close();
    //                             return;
    //                         }
    //                         if (!client->write(eiv)) {
    //                             client->close();
    //                             return;
    //                         }
    //                     } else {
    //                         int st = 0;
    //                         client->write(&st);
    //                     }
    //                     client->close();
    //                 }
    //                 if (op) {
    //                     try {
    //                         byte st = 0;
    //                         string token;
    //                         try {
    //                             if (!client->read(token)) {
    //                                 client->close();
    //                                 return;
    //                             }
    //                             token = de.decrypt(token);
    //                             token = token.substr(0, strlen(token.data()));
    //                             st = 1;
    //                         } catch (...) {
    //                             std::cout << "Failed in certificate" << endl;
    //                         }
    //                         if (!client->write(&st) || !st) {
    //                             client->close();
    //                             return;
    //                         }
    //                         if (sessions.find(token) == sessions.end()) {
    //                             client->close();
    //                             return;
    //                         }
    //                         auto session = sessions[token];
    //                         TcpServer transmit("0.0.0.0", 0);
    //                         int port = transmit.getPort();
    //                         string pstr = string((char *) &port, 4);
    //                         pstr = session.rsa.encrypt(pstr);
    //                         if (!client->write(pstr)) {
    //                             transmit.close();
    //                             return;
    //                         }
    //                         client->close();
    //                         bool fastmode = int(op) == 2;
    //                         auto request = shared_ptr<TcpClient>(transmit.accept(5));
    //                         transmit.close();
    //                         if (request == nullptr) {
    //                             continue;
    //                         }
    //                         request->setNoDelay(fastmode);
    //                         OcelotChannel ocelot = OcelotChannel(request.get(), &session.aes);
    //                         string buffer;
    //                         auto addr = parseAddr(ocelot, buffer);
    //                         // cout << "Fetch ip addr : " << addr.ip << " port :" << addr.port;
    //                         if (addr.port == -1 && addr.ip == "") {
    //                             return;
    //                         }
    //                         if (fastmode)
    //                             cout << " in fast mode" << endl;
    //                         cout << endl;
    //                         TcpClient target(addr.ip, addr.port);
    //                         target.setNoDelay(fastmode);
    //                         target.Output(buffer);
    //                     } catch (...) {
    //                         cout << "Failed to establish connection!" << endl;
    //                     }
    //                 }
    //             } catch (...) {
    //                 cout << "Client closed without sending any message!" << endl;
    //             }
    //         }
    //     }
    // };
}

#endif
