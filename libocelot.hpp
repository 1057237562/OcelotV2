#ifndef _LIBOCELOT_HPP_
#define _LIBOCELOT_HPP_

#include "crypt"
#include "tpool"
#include "unisocket"
#include <algorithm>
#include <iostream>
#include <map>
#include <mutex>
#include <ostream>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>
#include <thread>
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

typedef unsigned char byte;

class OcelotChannel : public NetworkStream {
protected:
    shared_ptr<TcpClient> socket;
    AES_CBC* aes;

public:
    OcelotChannel(shared_ptr<TcpClient> client, AES_CBC* aes)
        : socket(client)
        , aes(aes)
    {
    }

    void write(std::string& str)
    {
        int len = str.length();
        string slen = string((char*)&len, 4);
        slen = aes->encrypt(slen);
        socket->write(slen, 16);
        socket->write(str, len);
    }

    bool read(std::string& str)
    {
        byte header[16];
        if (!socket->read(&header))
            return false;
        string slen = string((char*)header, 16);
        slen = aes->decrypt(slen);
        int len;
        memcpy(&len, slen.data(), 4);
        std::string buf;
        if (!socket->read(buf, len))
            return false;
        str = aes->decrypt(buf);
        return true;
    }

    int Input(std::string& buf) override
    {
        try {
            byte header[16];
            if (!socket->read(&header))
                return 0;
            string slen = string((char*)header, 16);
            slen = aes->decrypt(slen);
            int len;
            memcpy(&len, slen.data(), 4);
            if (!socket->read(buf, len))
                return 0;
            buf = aes->decrypt(buf);
        } catch (runtime_error _) {
            return 0;
        }
        return buf.length();
    }

    bool Output(std::string& buf) override
    {
        std::string data = aes->encrypt(buf);

        int len = data.length();
        string slen = string((char*)&len, 4);
        slen = aes->encrypt(slen);
        if (!socket->write(slen, 16))
            return false;

        if (!socket->write(data, len))
            return false;
        return true;
    }

    bool isClosed() override
    {
        return socket->isClosed();
    }
};

class OcelotClient {

protected:
    TcpClient& socket;
    string usertoken;
    AES_CBC aes;

public:
    OcelotClient(TcpClient& client, string user, string password)
        : socket(client)
        , usertoken(user + "\n" + password)
    {
    }

    void handshake()
    {
        socket.write(&"");
        string key, iv;
        socket.read(key);
        RSA_PKCS1_OAEP en;
        en.fromX509PublicKey(key);

        RSA_PKCS1_OAEP de;
        de.generateKey();
        string pkey = de.getX509PublicKey();
        socket.read(pkey);

        string token = en.encrypt(usertoken);
        socket.write(token);

        string response;
        socket.read(response);
        key = de.decrypt(response);
        socket.read(response);
        iv = de.decrypt(response);
        aes = AES_CBC(key, iv);
    }
};

inline NetworkAddr parseAddr(OcelotChannel client, string& buffer)
{
    NetworkAddr res = { "", -1 };
    if (!client.read(buffer))
        return res;
    switch (buffer[3]) {
    case 0x01:
        buffer = buffer.substr(4);
        res.ip = to_string((byte)buffer[0]) + "." + to_string((byte)buffer[1]) + "." + to_string((byte)buffer[2]) + "." + to_string((byte)buffer[3]);
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
    }
    res.port = (int)(byte)buffer[0] << 8 | (int)(byte)buffer[1];
    buffer = buffer.substr(2);
    return res;
}

class OcelotServer {
private:
    threadpool::ThreadPool threadpool;
    std::map<unisocket::TcpClient*, std::thread*> workers;
    std::mutex mtx;

protected:
    struct Session {
        RSA_PKCS1_OAEP rsa;
        AES_CBC aes;
    };
    unisocket::TcpServer server;
    vector<string> tokens;
    map<string, Session> sessions;
    RSA_PKCS1_OAEP de;

public:
    OcelotServer(unisocket::TcpServer server, vector<string> tks)
        : server(server)
        , tokens(tks)
    {
        de.generateKey();
        sort(this->tokens.begin(), this->tokens.end());
    }

    void start()
    {
        while (true) {
            auto client = server.accept();
            client->setRecvTimeout(5);
            client->setSendTimeout(5);
            thread handler = thread([&](auto client) {
                try {
                    char op;
                    if (!client->read(&op)) {
                        client->close();
                        return;
                    }
                    if (!op) {
                        string pkey = de.getX509PublicKey();
                        if (!client->write(pkey)) {
                            client->close();
                            return;
                        }

                        string key, iv;
                        RSA_PKCS1_OAEP en;
                        if (!client->read(pkey)) {
                            client->close();
                            return;
                        }
                        en.fromX509PublicKey(pkey);

                        string token;
                        if (!client->read(token)) {
                            client->close();
                            return;
                        }
                        token = de.decrypt(token);
                        token = token.substr(0, strlen(token.data()));
                        key = random_string(32 + 16), iv = key.substr(32, 16);
                        key = key.substr(0, 32);
                        AES_CBC aes(key, iv);
                        string ekey = en.encrypt(key);
                        string eiv = en.encrypt(iv);
                        if (binary_search(tokens.begin(), tokens.end(), token)) {
                            sessions[token] = { en, aes };
                            cout << "Session established with" << endl
                                 << token << endl;
                            if (!client->write(ekey)) {
                                client->close();
                                return;
                            }
                            if (!client->write(eiv)) {
                                client->close();
                                return;
                            }
                        } else {
                            int st = 0;
                            client->write(&st);
                        }

                        client->close();
                    }
                    if (op) {
                        try {
                            byte st = 0;
                            string token;
                            try {
                                if (!client->read(token)) {
                                    client->close();
                                    return;
                                }
                                token = de.decrypt(token);
                                token = token.substr(0, strlen(token.data()));
                                st = 1;
                            } catch (...) {
                                std::cout << "Failed in certificate" << endl;
                            }
                            if (!client->write(&st) || !st) {
                                client->close();
                                return;
                            }
                            if (sessions.find(token) == sessions.end()) {
                                client->close();
                                return;
                            }
                            auto session = &sessions[token];
                            TcpServer* transmit = new TcpServer("0.0.0.0", 0);
                            int port = transmit->getPort();
                            string pstr = string((char*)&port, 4);
                            pstr = session->rsa.encrypt(pstr);
                            if (!client->write(pstr)) {
                                transmit->close();
                                return;
                            }
                            client->close();
                            bool fastmode = int(op) == 2;
                            thread th;
                            try {
                                auto request = transmit->accept(5);
                                transmit->close();
                                request->setNoDelay(fastmode);
                                OcelotChannel ocelot = OcelotChannel(request, &session->aes);
                                try {
                                    string buffer;
                                    auto addr = parseAddr(ocelot, buffer);
                                    cout << "Fetch ip addr : " << addr.ip << " port :" << addr.port;
                                    if (addr.port == -1 && addr.ip == "") {
                                        return;
                                    }
                                    if (fastmode)
                                        cout << " in fast mode" << endl;
                                    cout << endl;
                                    TcpClient target = TcpClient(addr.ip, addr.port);
                                    target.setNoDelay(fastmode);
                                    target.Output(buffer);
                                    th = thread([&]() {
                                        try {
                                            copyTo(&ocelot, &target);
                                        } catch (runtime_error _) {
                                        }
                                        target.close();
                                    });
                                    try {
                                        copyTo(&target, &ocelot);
                                    } catch (runtime_error _) {
                                    }
                                    request->close();
                                    cout << "Connection to " << addr.ip << ":" << addr.port << " closed" << endl;
                                } catch (...) {
                                    cout << "Connection shut unexpectedly!" << endl;
                                }
                            } catch (...) {
                                cout << "Connection shut unexpectedly!" << endl;
                            }
                            if (th.joinable())
                                th.join();
                            delete transmit;
                        } catch (...) {
                            client->close();
                            cout << "Request link handshake failed!" << endl;
                        }
                    }
                } catch (...) {
                    cout << "Client closed without sending any message!" << endl;
                }
            },
                client);
            if (handler.joinable())
                handler.detach();
        }
    }
};
}

#endif