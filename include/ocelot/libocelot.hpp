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
#include <unordered_set>
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
            // As with PassiveSocket::copyTo, this queued handler must not own
            // the opposite half of the tunnel or the pair becomes a permanent
            // shared_ptr cycle after close.
            const weak_ptr<PassiveSocket> weak_target = target;
            que.emplace(-static_cast<long long>(AES_BLOCK),
                        [this, weak_target](char *buf, const int len, SOCKET,
                                            const shared_ptr<PassiveSocket> &) {
                            const auto target = weak_target.lock();
                            if (!target || !feed(buf, static_cast<size_t>(len), target))
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

    /// A UDP association cannot use TCP half-close meaningfully: the tunnel is
    /// only a framed carrier for bidirectional datagrams.  Treating EOF like a
    /// streaming TCP relay would keep its descriptor pair around until the
    /// generic half-close timeout, so report it as terminal immediately.
    class PassiveUdpChannel final : public PassiveOcelotChannel {
    public:
        explicit PassiveUdpChannel(shared_ptr<AES_CBC> aes) : PassiveOcelotChannel(std::move(aes)) {}

        int recvData(const SOCKET socket, const shared_ptr<PassiveSocket> &current) override {
            const int result = PassiveOcelotChannel::recvData(socket, current);
            return result == 0 ? -1 : result;
        }
    };

    constexpr size_t UDP_PACKET_MAX = 65507;

    /// Keeps the TCP connection associated with SOCKS5 UDP ASSOCIATE open.
    /// RFC 1928 defines the lifetime of the UDP relay by this TCP connection;
    /// bytes sent after the request are ignored, while EOF tears down the
    /// entire association through the close callbacks installed by the client.
    class PassiveUdpAssociationControl final : public PassiveSocket {
    public:
        PassiveUdpAssociationControl() {
            que.emplace(-1, [](char *, int, SOCKET, const shared_ptr<PassiveSocket> &) {});
        }
    };

    /// Client-side UDP endpoint.  It accepts SOCKS5 UDP packets from the first
    /// local sender and moves each complete datagram into one encrypted tunnel
    /// frame.  Responses already contain a SOCKS5 UDP header and are returned
    /// to the same local sender unchanged.
    class PassiveLocalUdp final : public PassiveSocket {
        sockaddr_in client{};
        bool client_known = false;

    public:
        int recvData(const SOCKET socket, const shared_ptr<PassiveSocket> &) override {
            char buffer[UDP_PACKET_MAX];
            for (int datagrams = 0; datagrams < 64; ++datagrams) {
                sockaddr_in source{};
                socklen_t source_length = sizeof(source);
                const int received = recvfrom(socket, buffer, sizeof(buffer), 0,
                                              reinterpret_cast<sockaddr *>(&source), &source_length);
                if (received < 0)
                    return wouldBlock() ? 1 : -1;
                if (received == 0)
                    continue;

                const string packet(buffer, static_cast<size_t>(received));
                if (!parseSocks5Udp(packet).valid())
                    continue;
                if (!client_known) {
                    client = source;
                    client_known = true;
                } else if (client.sin_addr.s_addr != source.sin_addr.s_addr || client.sin_port != source.sin_port) {
                    continue;
                }

                noteActivity();
                const auto channel = peer.lock();
                if (!channel)
                    return 0;
                // UDP has no sender-side backpressure.  Dropping under tunnel
                // congestion preserves bounded memory and native UDP
                // semantics instead of growing the TCP write queue forever.
                if (channel->pendingBytes() <= WRITE_HIGH_WATER)
                    channel->write(packet.data(), static_cast<int>(packet.size()));
            }
            return 1; // fairness: let epoll service other sockets before more UDP
        }

        void write(const char *buffer, const int length) override {
            if (!client_known || dead || length <= 0)
                return;
            const int sent = sendto(socket_fd, buffer, length, SEND_FLAGS,
                                    reinterpret_cast<const sockaddr *>(&client), sizeof(client));
            if (sent >= 0)
                noteActivity();
            // UDP delivery is best effort.  A full socket buffer, an oversized
            // response or a transient routing error drops only this datagram;
            // none of them should retire the long-lived association.
        }
    };

    /// Server-side UDP endpoint.  Plaintext tunnel frames are SOCKS5 UDP
    /// packets; their destination is resolved and sent with sendto().  Replies
    /// are accepted only from endpoints previously contacted by this
    /// association, wrapped with their source address and sent back encrypted.
    class PassiveRemoteUdp final : public PassiveSocket {
        unordered_set<uint64_t> allowed_sources;

        static uint64_t endpointKey(const sockaddr_in &address) {
            return static_cast<uint64_t>(address.sin_addr.s_addr) << 16 | address.sin_port;
        }

    public:
        int recvData(const SOCKET socket, const shared_ptr<PassiveSocket> &) override {
            char buffer[UDP_PACKET_MAX];
            for (int datagrams = 0; datagrams < 64; ++datagrams) {
                sockaddr_in source{};
                socklen_t source_length = sizeof(source);
                const int received = recvfrom(socket, buffer, sizeof(buffer), 0,
                                              reinterpret_cast<sockaddr *>(&source), &source_length);
                if (received < 0)
                    return wouldBlock() ? 1 : -1;
                if (allowed_sources.find(endpointKey(source)) == allowed_sources.end())
                    continue;

                // The SOCKS5 wrapper adds ten bytes.  A larger origin reply
                // cannot be emitted as one legal IPv4 UDP datagram, so drop it
                // without poisoning the rest of the association.
                if (static_cast<size_t>(received) > UDP_PACKET_MAX - 10)
                    continue;

                noteActivity();
                const auto channel = peer.lock();
                if (!channel)
                    return 0;
                if (channel->pendingBytes() <= WRITE_HIGH_WATER) {
                    const string packet = wrapSocks5Udp(source, buffer, static_cast<size_t>(received));
                    channel->write(packet.data(), static_cast<int>(packet.size()));
                }
            }
            return 1;
        }

        void write(const char *buffer, const int length) override {
            if (dead || length <= 0)
                return;
            const string packet(buffer, static_cast<size_t>(length));
            const UdpPacket parsed = parseSocks5Udp(packet);
            if (!parsed.valid())
                return;

            uint32_t resolved = 0;
            if (!resolveHost(parsed.destination.ip, resolved))
                return;
            sockaddr_in destination{};
            destination.sin_family = AF_INET;
            destination.sin_addr.s_addr = resolved;
            destination.sin_port = htons(parsed.destination.port);
            const char *payload = packet.data() + parsed.payload_offset;
            const size_t payload_length = packet.size() - parsed.payload_offset;
            const int sent = sendto(socket_fd, payload, static_cast<int>(payload_length), SEND_FLAGS,
                                    reinterpret_cast<const sockaddr *>(&destination), sizeof(destination));
            if (sent >= 0) {
                if (allowed_sources.size() >= 4096)
                    allowed_sources.clear();
                allowed_sources.insert(endpointKey(destination));
                noteActivity();
            }
            // sendto() failures affect this datagram only; keeping the socket
            // alive lets subsequent destinations continue to work.
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
        // Long enough to cover ordinary TCP SYN retransmissions on a lossy
        // WAN, while still bounding the number of abandoned random ports.
        static constexpr auto RELAY_ACCEPT_TIMEOUT = chrono::seconds(30);
        static constexpr auto CONTROL_STAGE_TIMEOUT = chrono::seconds(30);

        shared_ptr<RSA_PKCS1_OAEP> encryptor = make_shared<RSA_PKCS1_OAEP>();
        shared_ptr<RSA_PKCS1_OAEP> decrypter;
        shared_ptr<Epoll> allocated_epoll;
        vector<string> &tks;
        map<string, shared_ptr<AES_CBC> > &keys;
        bool authenticated = false;

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
            if (authenticated)
                clearExpiry(); // authenticated control links may idle forever
            else
                expireWhenIdleFor(chrono::duration_cast<chrono::milliseconds>(CONTROL_STAGE_TIMEOUT));
            read<char>([](const char op, SOCKET, const shared_ptr<PassiveSocket> &sock) {
                const auto self = static_pointer_cast<PassiveOcelotControl>(sock);
                switch (op ^ 'O') {
                    case 0:
                        self->expireWhenIdleFor(
                            chrono::duration_cast<chrono::milliseconds>(CONTROL_STAGE_TIMEOUT));
                        self->beginHandshake(sock);
                        break;
                    case 1:
                        self->expireWhenIdleFor(
                            chrono::duration_cast<chrono::milliseconds>(CONTROL_STAGE_TIMEOUT));
                        self->beginOpen(sock);
                        break;
                    case 2:
                        self->expireWhenIdleFor(
                            chrono::duration_cast<chrono::milliseconds>(CONTROL_STAGE_TIMEOUT));
                        self->beginOpenUdp(sock);
                        break;
                    default:
                        LOG_WARN("unknown control opcode 0x%02x", static_cast<unsigned char>(op));
                        self->closeAfterWrite();
                }
            });
        }

    protected:
        void beginHandshake(const shared_ptr<PassiveSocket> &sock) {
            try {
                sock->write(X509PublicKey(decrypter->getX509PublicKey()));
            } catch (const runtime_error &e) {
                LOG_ERROR("cannot publish server key: %s", e.what());
                sock->closeAfterWrite();
                return;
            }

            sock->read<X509PublicKey>([](X509PublicKey key, SOCKET, const shared_ptr<PassiveSocket> &c) {
                try {
                    static_pointer_cast<PassiveOcelotControl>(c)->encryptor->fromX509PublicKey(key);
                } catch (const runtime_error &e) {
                    LOG_WARN("client sent an unusable public key: %s", e.what());
                    c->closeAfterWrite();
                }
            });

            sock->read<SHA256Digest>([](SHA256Digest digest, SOCKET, const shared_ptr<PassiveSocket> &c) {
                const auto self = static_pointer_cast<PassiveOcelotControl>(c);
                const string token(digest.data, sizeof(digest.data));
                int rejected = 0, accepted = 1;
                if (!binary_search(self->tks.begin(), self->tks.end(), token)) {
                    LOG_WARN("authentication rejected");
                    c->write(rejected);
                    c->closeAfterWrite();
                    return;
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
                    c->closeAfterWrite();
                    return;
                }
                LOG_INFO("session established");
                self->authenticated = true;
                self->arm();
            });
        }

        void beginOpen(const shared_ptr<PassiveSocket> &sock) {
            sock->read<SHA256Digest>([](SHA256Digest digest, SOCKET, const shared_ptr<PassiveSocket> &c) {
                const auto self = static_pointer_cast<PassiveOcelotControl>(c);
                const auto entry = self->keys.find(string(digest.data, sizeof(digest.data)));
                if (entry == self->keys.end()) {
                    LOG_WARN("relay requested with an unknown session token");
                    c->closeAfterWrite();
                    return;
                }
                const auto aes = entry->second;

                c->read<AESBlock>([aes](AESBlock block, SOCKET, const shared_ptr<PassiveSocket> &c) {
                    uint32_t len = 0;
                    try {
                        const string header = aes->decrypt(block);
                        if (header.size() < sizeof(len))
                            return c->closeAfterWrite();
                        memcpy(&len, header.data(), sizeof(len));
                    } catch (const runtime_error &) {
                        LOG_WARN("relay request header failed to decrypt");
                        c->closeAfterWrite();
                        return;
                    }
                    if (len == 0 || len > MAX_REQUEST) {
                        LOG_WARN("relay request length %u is out of range", len);
                        c->closeAfterWrite();
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

        void beginOpenUdp(const shared_ptr<PassiveSocket> &sock) {
            sock->read<SHA256Digest>([](SHA256Digest digest, SOCKET, const shared_ptr<PassiveSocket> &c) {
                const auto self = static_pointer_cast<PassiveOcelotControl>(c);
                const auto entry = self->keys.find(string(digest.data, sizeof(digest.data)));
                if (entry == self->keys.end()) {
                    LOG_WARN("UDP relay requested with an unknown session token");
                    c->closeAfterWrite();
                    return;
                }
                self->openUdpRelay(c, entry->second);
                self->arm();
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

            const weak_ptr<Epoll> weak_ep = ep;
            const auto server = make_shared<PassiveServer>(
                [aes, addr, weak_ep](const shared_ptr<TcpClient> &request,
                                     const shared_ptr<PassiveSocket> &) {
                    const auto ep = weak_ep.lock();
                    if (!ep) {
                        LOG_WARN("relay worker stopped before the client connected");
                        return;
                    }
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
            // If the client disappears after receiving the allocated port,
            // this listener otherwise has no event that could ever retire it.
            // The timeout covers only the pre-connect rendezvous; once accept
            // succeeds, the resulting tunnel has no ordinary idle deadline.
            server->expireAfter(chrono::duration_cast<chrono::milliseconds>(RELAY_ACCEPT_TIMEOUT));
            ep->registerSocket(listener, server);
            reply(control, aes, port);
        }

        void openUdpRelay(const shared_ptr<PassiveSocket> &control, const shared_ptr<AES_CBC> &aes) {
            const auto ep = allocated_epoll;
            SOCKET listener;
            uint32_t port;
            try {
                const TcpServer transmit("0.0.0.0", 0);
                listener = transmit.getFD();
                port = static_cast<uint32_t>(transmit.getPort());
            } catch (const runtime_error &e) {
                LOG_ERROR("cannot open a UDP tunnel port: %s", e.what());
                return reply(control, aes, 0);
            }

            const weak_ptr<Epoll> weak_ep = ep;
            const auto server = make_shared<PassiveServer>(
                [aes, weak_ep](const shared_ptr<TcpClient> &request, const shared_ptr<PassiveSocket> &) {
                    const auto ep = weak_ep.lock();
                    if (!ep)
                        return;
                    try {
                        UdpSocket outbound("0.0.0.0", 0);
                        const auto udp = make_shared<PassiveRemoteUdp>();
                        const auto channel = make_shared<PassiveUdpChannel>(aes);
                        channel->copyTo(udp);
                        PassiveSocket::link(udp, channel);
                        ep->registerSocket(outbound.release(), udp);
                        ep->registerSocket(request->release(), channel);
                        LOG_INFO("UDP relay association established");
                    } catch (const runtime_error &e) {
                        LOG_WARN("cannot create UDP relay association: %s", e.what());
                    }
                }, true);
            server->expireAfter(chrono::duration_cast<chrono::milliseconds>(RELAY_ACCEPT_TIMEOUT));
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
