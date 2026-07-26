#ifndef OCELOT_LIBOCELOT_HPP
#define OCELOT_LIBOCELOT_HPP

#include "crypto.hpp"
#include "io.hpp"
#include "logging.hpp"
#include "protocol.hpp"
#include "unisocket.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ocelot {
    using namespace std;
    using namespace unisocket;
    using namespace crypto;
    using namespace protocol;
    using namespace io;

    /// One end of an encrypted tunnel.
    ///
    /// Wire format (identical in both directions):
    ///
    ///     [16] AES(uint32 body_length)
    ///     [n ] AES(payload)
    ///
    /// The previous format appended the literal marker "Ocelot3" to the
    /// plaintext and left the receiver to find the frame boundary by trying to
    /// decrypt the whole accumulated buffer once per 16-byte block and looking
    /// for the marker.  That is quadratic in frame size, and every failed
    /// attempt threw and caught a std::runtime_error: relaying a single 8 KiB
    /// record cost ~512 decryptions of a growing buffer plus ~511 thrown
    /// exceptions.  An explicit length prefix costs exactly two AES operations
    /// per frame and cannot false-positive on payload that happens to contain
    /// the marker.
    class PassiveOcelotChannel : public PassiveSocket {
    protected:
        static constexpr size_t HEADER_SIZE = sizeof(AESBlock);
        static constexpr size_t AES_BLOCK = sizeof(AESBlock);
        static constexpr uint32_t MAX_FRAME = 64 * 1024;

        shared_ptr<AES_CBC> aes;
        string pending; ///< ciphertext bytes not yet forming a whole frame
        uint32_t expect = 0; ///< body bytes awaited, 0 == awaiting a header
        bool protocol_error = false;

    public:
        explicit PassiveOcelotChannel(shared_ptr<AES_CBC> aes) : aes(std::move(aes)) {}

        void write(const char *buf, const int len) override {
            if (len <= 0)
                return;
            string frame;
            try {
                const string body = aes->encrypt(string(buf, len));
                const uint32_t body_len = static_cast<uint32_t>(body.size());
                frame = aes->encrypt(convertBit(body_len));
                frame.reserve(frame.size() + body.size());
                frame.append(body);
            } catch (const runtime_error &e) {
                LOG_WARN("tunnel encrypt failed: %s", e.what());
                protocol_error = true;
                return;
            }
            // Header and body go out in one send() so a frame never crosses an
            // event-loop boundary and never gets split across two segments.
            PassiveSocket::write(frame.data(), static_cast<int>(frame.size()));
        }

        void copyTo(const shared_ptr<PassiveSocket> &target) override {
            while (!que.empty())
                que.pop();
            ptr = 0;
            pending.clear();
            expect = 0;
            protocol_error = false;
            que.emplace(-static_cast<long long>(AES_BLOCK),
                        [this, target](char *buf, const int len, SOCKET, const shared_ptr<PassiveSocket> &) {
                            if (!feed(buf, static_cast<size_t>(len), target))
                                protocol_error = true;
                        });
        }

        int recvData(const SOCKET socket, const shared_ptr<PassiveSocket> &current) override {
            const int r = PassiveSocket::recvData(socket, current);
            return protocol_error ? -1 : r;
        }

    protected:
        /// Consumes as many whole frames as `data` holds; `off` is advanced past
        /// them.  Returns false on an unrecoverable framing/crypto error.
        bool parse(const char *data, const size_t size, size_t &off, const shared_ptr<PassiveSocket> &target) {
            for (;;) {
                if (expect == 0) {
                    if (size - off < HEADER_SIZE)
                        return true;
                    string head;
                    try {
                        head = aes->decrypt(string(data + off, HEADER_SIZE));
                    } catch (const runtime_error &) {
                        LOG_WARN("tunnel header failed to decrypt");
                        return false;
                    }
                    if (head.size() < sizeof(uint32_t))
                        return false;
                    memcpy(&expect, head.data(), sizeof(uint32_t));
                    if (expect == 0 || expect > MAX_FRAME || expect % AES_BLOCK != 0) {
                        LOG_WARN("tunnel frame length %u is out of range", expect);
                        return false;
                    }
                    off += HEADER_SIZE;
                } else {
                    if (size - off < expect)
                        return true;
                    string plain;
                    try {
                        plain = aes->decrypt(string(data + off, expect));
                    } catch (const runtime_error &) {
                        LOG_WARN("tunnel body failed to decrypt");
                        return false;
                    }
                    off += expect;
                    expect = 0;
                    target->write(plain.data(), static_cast<int>(plain.size()));
                }
            }
        }

        bool feed(char *buf, const size_t len, const shared_ptr<PassiveSocket> &target) {
            size_t off = 0;
            if (pending.empty()) {
                // Common case: parse straight out of the read buffer and only
                // stash the trailing partial frame.
                if (!parse(buf, len, off, target))
                    return false;
                if (off < len)
                    pending.assign(buf + off, len - off);
                return true;
            }
            pending.append(buf, len);
            if (!parse(pending.data(), pending.size(), off, target))
                return false;
            if (off)
                pending.erase(0, off);
            return true;
        }
    };

    /// Server end of the control link.
    ///
    /// Every handler re-arms the opcode read when it finishes, so one control
    /// connection now serves an unlimited number of relay requests.  Previously
    /// the queue simply ran dry, the client had to open (and the server had to
    /// accept, epoll-register and tear down) a fresh TCP connection plus a full
    /// round trip for every single proxied request.
    class PassiveOcelotControl : public PassiveSocket {
    protected:
        static constexpr uint32_t MAX_REQUEST = 1024;

        shared_ptr<RSA_PKCS1_OAEP> encryptor = make_shared<RSA_PKCS1_OAEP>();
        shared_ptr<RSA_PKCS1_OAEP> decrypter;
        shared_ptr<Epoll> allocated_epoll;
        vector<string> &tks;
        map<string, shared_ptr<AES_CBC> > &keys;

    public:
        PassiveOcelotControl(shared_ptr<RSA_PKCS1_OAEP> de, shared_ptr<Epoll> allocate, vector<string> &tokens,
                             map<string, shared_ptr<AES_CBC> > &mp)
            : decrypter(std::move(de)), allocated_epoll(std::move(allocate)), tks(tokens), keys(mp) {
            arm();
        }

        /// Waits for the next opcode.  Handlers that decide the peer is not
        /// worth talking to simply do not call this again, which drops the
        /// connection instead of leaving a desynchronised stream open.
        void arm() {
            read<char>([](const char op, SOCKET, const shared_ptr<PassiveSocket> &sock) {
                const auto self = static_pointer_cast<PassiveOcelotControl>(sock);
                switch (op ^ 'O') {
                    case 0:
                        self->beginHandshake(sock);
                        break;
                    case 1:
                        self->beginOpen(sock);
                        break;
                    default:
                        LOG_WARN("unknown control opcode 0x%02x", static_cast<unsigned char>(op));
                }
            });
        }

    protected:
        void beginHandshake(const shared_ptr<PassiveSocket> &sock) {
            try {
                sock->write(X509PublicKey(decrypter->getX509PublicKey()));
            } catch (const runtime_error &e) {
                LOG_ERROR("cannot publish server key: %s", e.what());
                return;
            }

            sock->read<X509PublicKey>([](X509PublicKey key, SOCKET, const shared_ptr<PassiveSocket> &c) {
                try {
                    static_pointer_cast<PassiveOcelotControl>(c)->encryptor->fromX509PublicKey(key);
                } catch (const runtime_error &e) {
                    LOG_WARN("client sent an unusable public key: %s", e.what());
                }
            });

            sock->read<SHA256Digest>([](SHA256Digest digest, SOCKET, const shared_ptr<PassiveSocket> &c) {
                const auto self = static_pointer_cast<PassiveOcelotControl>(c);
                const string token(digest.data, sizeof(digest.data));
                int rejected = 0, accepted = 1;
                if (!binary_search(self->tks.begin(), self->tks.end(), token)) {
                    LOG_WARN("authentication rejected");
                    c->write(rejected);
                    return; // no re-arm: drop the connection
                }
                try {
                    const string material = random_string(32 + 16);
                    // Encrypt before answering, so a failure here still gets a
                    // rejection out instead of leaving the client waiting.
                    const string block = self->encryptor->encrypt(material);
                    c->write(accepted);
                    c->write(RSABlock(block));
                    self->keys[token] = make_shared<AES_CBC>(material.substr(0, 32), material.substr(32, 16));
                } catch (const runtime_error &e) {
                    LOG_WARN("session key exchange failed: %s", e.what());
                    c->write(rejected);
                    return;
                }
                LOG_INFO("session established");
                self->arm();
            });
        }

        void beginOpen(const shared_ptr<PassiveSocket> &sock) {
            sock->read<SHA256Digest>([](SHA256Digest digest, SOCKET, const shared_ptr<PassiveSocket> &c) {
                const auto self = static_pointer_cast<PassiveOcelotControl>(c);
                const auto entry = self->keys.find(string(digest.data, sizeof(digest.data)));
                if (entry == self->keys.end()) {
                    LOG_WARN("relay requested with an unknown session token");
                    return;
                }
                const auto aes = entry->second;

                c->read<AESBlock>([aes](AESBlock block, SOCKET, const shared_ptr<PassiveSocket> &c) {
                    uint32_t len = 0;
                    try {
                        const string header = aes->decrypt(block);
                        if (header.size() < sizeof(len))
                            return;
                        memcpy(&len, header.data(), sizeof(len));
                    } catch (const runtime_error &) {
                        LOG_WARN("relay request header failed to decrypt");
                        return;
                    }
                    if (len == 0 || len > MAX_REQUEST) {
                        LOG_WARN("relay request length %u is out of range", len);
                        return;
                    }
                    c->read(static_cast<int>(len),
                            [len, aes](const char *body, SOCKET, const shared_ptr<PassiveSocket> &c) {
                                const auto self = static_pointer_cast<PassiveOcelotControl>(c);
                                // Copy before queueing anything else: the next
                                // read() may resize the buffer `body` points into.
                                const string request(body, len);
                                self->openRelay(c, aes, request);
                                // The stream is still in sync whatever happened
                                // to this particular request, so the control
                                // link survives a failed destination.
                                self->arm();
                            });
                });
            });
        }

        /// Opens a one-shot listener for this request and tells the client which
        /// port to come back on.  A reply is always sent -- port 0 means "this
        /// request failed" -- so the client never blocks waiting for an answer
        /// that is not coming.
        void openRelay(const shared_ptr<PassiveSocket> &control, const shared_ptr<AES_CBC> &aes,
                       const string &request) {
            NetworkAddr addr;
            try {
                addr = parseSocks5(aes->decrypt(request));
            } catch (const runtime_error &e) {
                LOG_WARN("relay request failed to decrypt: %s", e.what());
                return reply(control, aes, 0);
            }
            if (!addr.valid()) {
                LOG_WARN("relay request carried an unusable destination");
                return reply(control, aes, 0);
            }

            const auto ep = allocated_epoll;
            SOCKET listener;
            uint32_t port;
            try {
                const TcpServer transmit("0.0.0.0", 0);
                listener = transmit.getFD();
                port = static_cast<uint32_t>(transmit.getPort());
            } catch (const runtime_error &e) {
                LOG_ERROR("cannot open a relay port: %s", e.what());
                return reply(control, aes, 0);
            }

            const auto server = make_shared<PassiveServer>(
                [aes, addr, ep](const shared_ptr<TcpClient> &request, const shared_ptr<PassiveSocket> &) {
                    LOG_INFO("relaying to %s:%d", addr.ip.c_str(), addr.port);
                    shared_ptr<TcpClient> target;
                    try {
                        // Non-blocking: a slow or dead destination no longer
                        // freezes every other tunnel sharing this epoll thread.
                        target = shared_ptr<TcpClient>(TcpClient::connectAsync(addr.ip, addr.port));
                    } catch (const runtime_error &e) {
                        LOG_WARN("cannot reach %s:%d (%s)", addr.ip.c_str(), addr.port, e.what());
                        return;
                    }
                    const auto passive = make_shared<PassiveSocket>();
                    const auto channel = make_shared<PassiveOcelotChannel>(aes);
                    passive->copyTo(channel);
                    channel->copyTo(passive);
                    PassiveSocket::link(passive, channel);
                    ep->registerSocket(request->release(), channel);
                    ep->registerSocket(target->release(), passive);
                }, true);
            ep->registerSocket(listener, server);
            reply(control, aes, port);
        }

        static void reply(const shared_ptr<PassiveSocket> &control, const shared_ptr<AES_CBC> &aes,
                          const uint32_t port) {
            try {
                control->write(AESBlock(aes->encrypt(convertBit(port))));
            } catch (const runtime_error &e) {
                LOG_WARN("cannot answer the control link: %s", e.what());
            }
        }
    };

    class EpollOcelot {
        Epoll epoll;
        TcpServer server;
        vector<string> tokens;
        shared_ptr<RSA_PKCS1_OAEP> de = make_shared<RSA_PKCS1_OAEP>();
        map<string, shared_ptr<AES_CBC> > keys;
        vector<shared_ptr<Epoll> > bucket;
        atomic_bool closed{false};
        size_t next = 0;

    public:
        EpollOcelot(const TcpServer &server, vector<string> tks, int core = 1)
            : server(server), tokens(std::move(tks)) {
            de->generateKey();
            sort(tokens.begin(), tokens.end());
            if (core < 1)
                core = 1;
            // vector::resize(n, value) copies the *same* shared_ptr n times, so
            // every "core" used to share one epoll thread.
            bucket.reserve(core);
            for (int i = 0; i < core; i++)
                bucket.emplace_back(make_shared<Epoll>());
        }

        ~EpollOcelot() { closed = true; }

        void stop() { closed = true; }

        void start() {
            while (!closed) {
                const auto client = shared_ptr<TcpClient>(server.accept());
                if (!client) {
                    if (wouldBlock())
                        continue;
                    LOG_ERROR("accept failed: %d", getErrorCode());
                    break;
                }
                epoll.registerSocket(client->release(),
                                     make_shared<PassiveOcelotControl>(de, bucket[next], tokens, keys));
                next = (next + 1) % bucket.size();
            }
        }
    };
}

#endif
