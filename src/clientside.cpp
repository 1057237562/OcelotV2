#include <cstdlib>
#include <memory>
#include <string>

#include "ocelot/libocelot.hpp"
#include "ocelot/logging.hpp"
#include "ocelot/protocol.hpp"

using namespace std;
using namespace unisocket;
using namespace crypto;
using namespace protocol;
using namespace io;

namespace {
    string serverIp = "127.0.0.1";
    int serverPort = 2080;
    int listenPort = 3000;

    const auto userToken = SHA256Digest(sha256_string("libra\n65536forC"));

    constexpr int CONTROL_TIMEOUT_SECONDS = 30;
    constexpr int GREETING_TIMEOUT_SECONDS = 10;
    constexpr size_t MAX_HTTP_HEAD = 64 * 1024;

    shared_ptr<AES_CBC> aes;
    unique_ptr<TcpClient> control;

    /// Authenticates and derives the session key.  The same connection then
    /// stays open as the control link.
    bool handshake(TcpClient &client) {
        client.write('O');

        X509PublicKey pkey;
        if (!client.read(pkey))
            return false;
        RSA_PKCS1_OAEP en;
        en.fromX509PublicKey(pkey);

        RSA_PKCS1_OAEP de;
        de.generateKey();
        if (!client.write(X509PublicKey(de.getX509PublicKey())))
            return false;

        if (!client.write(userToken))
            return false;

        int state = 0;
        if (!client.read(state))
            return false;
        if (!state) {
            LOG_ERROR("Certification failed");
            return false;
        }

        RSABlock rsa_block;
        if (!client.read<RSABlock>(rsa_block))
            return false;
        const string material = de.decrypt(string(rsa_block.data, sizeof(rsa_block.data)));
        if (material.size() < 48)
            return false;
        aes = make_shared<AES_CBC>(material.substr(0, 32), material.substr(32, 16));
        LOG_INFO("Handshake complete");
        return true;
    }

    /// Brings the shared control link up, reconnecting after a server restart.
    bool ensureControl() {
        if (control && !control->isClosed())
            return true;
        try {
            auto link = make_unique<TcpClient>(serverIp, serverPort);
            link->setRecvTimeout(CONTROL_TIMEOUT_SECONDS);
            link->setSendTimeout(CONTROL_TIMEOUT_SECONDS);
            if (!handshake(*link))
                return false;
            control = std::move(link);
            return true;
        } catch (const runtime_error &e) {
            LOG_ERROR("cannot reach the Ocelot server: %s", e.what());
            return false;
        }
    }

    /// Asks the server for a relay port.  One connection now carries every
    /// request, so a proxied connection costs a single round trip instead of a
    /// fresh TCP handshake plus a round trip.
    ///
    /// The destination is encrypted inside the retry loop: reconnecting
    /// re-runs the handshake and derives a fresh session key, so a payload
    /// encrypted before the reconnect would be undecryptable afterwards.
    int openConnection(const string &address) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (!ensureControl())
                return 0;
            string cipher;
            AESBlock header, answer;
            try {
                cipher = aes->encrypt(address);
                const uint32_t len = static_cast<uint32_t>(cipher.size());
                header = AESBlock(aes->encrypt(convertBit(len)));
            } catch (const runtime_error &e) {
                LOG_ERROR("cannot encrypt the relay request: %s", e.what());
                return 0;
            }

            if (control->write(static_cast<char>('O' ^ 1))
                && control->write(userToken)
                && control->write(header)
                && control->write(cipher.data(), static_cast<int>(cipher.size()))
                && control->read<AESBlock>(answer)) {
                try {
                    const string portStr = aes->decrypt(answer);
                    if (portStr.size() >= sizeof(uint32_t)) {
                        uint32_t port;
                        memcpy(&port, portStr.data(), sizeof(port));
                        return static_cast<int>(port);
                    }
                } catch (const runtime_error &e) {
                    LOG_WARN("cannot decrypt the relay answer: %s", e.what());
                }
                return 0;
            }
            // The link died mid-request; drop it and retry once on a fresh one.
            LOG_WARN("control link lost, reconnecting");
            control.reset();
        }
        return 0;
    }

    /// Reads the local application's proxy greeting and returns the destination
    /// as a SOCKS5 address block.  `leftover` receives any bytes that were read
    /// past the end of the greeting, which must still reach the destination.
    string intercept(const shared_ptr<TcpClient> &request, string &leftover) {
        switch (certificate(request)) {
            case 5:
                return interceptSocks5(request);
            case 4: {
                string raw;
                if (!request->read(raw, 6))
                    return "";
                return socks4To5(raw);
            }
            case 1: {
                string head;
                char buf[4096];
                size_t end;
                for (;;) {
                    const int n = request->receive(buf, 0, sizeof(buf));
                    if (n <= 0)
                        return "";
                    head.append(buf, n);
                    end = head.find("\r\n\r\n");
                    if (end != string::npos)
                        break;
                    if (head.size() > MAX_HTTP_HEAD)
                        return "";
                }
                // A client that pipelines payload behind CONNECT used to have it
                // silently discarded.
                leftover = head.substr(end + 4);
                if (!request->write(httpSucceed.data(), static_cast<int>(httpSucceed.size())))
                    return "";
                return HttpToSocks5(head);
            }
            default:
                return "";
        }
    }
}

int main(const int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const string arg = argv[i];
        if (arg == "--server" && i + 1 < argc)
            serverIp = argv[++i];
        else if (arg == "--server-port" && i + 1 < argc)
            serverPort = atoi(argv[++i]);
        else if (arg == "--listen" && i + 1 < argc)
            listenPort = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s [--server IP] [--server-port N] [--listen N]\n", argv[0]);
            return 1;
        }
    }

    init();
    if (!ensureControl()) {
        LOG_ERROR("Cannot establish a session with %s:%d", serverIp.c_str(), serverPort);
        return 1;
    }

    const TcpServer server("0.0.0.0", listenPort);
    const auto epoll = make_shared<Epoll>();
    LOG_INFO("Ocelot client listening on port %d", listenPort);
    printf("Ocelot client listening on port %d\n", listenPort);
    fflush(stdout);

    for (;;) {
        const auto request = shared_ptr<TcpClient>(server.accept());
        if (!request) {
            if (wouldBlock())
                continue;
            LOG_ERROR("accept failed: %d", getErrorCode());
            break;
        }

        // The greeting is read synchronously, so a client that connects and
        // then says nothing would otherwise wedge the whole accept loop.  Once
        // the socket joins the event loop it becomes non-blocking and the
        // timeout no longer applies.
        request->setRecvTimeout(GREETING_TIMEOUT_SECONDS);
        request->setSendTimeout(GREETING_TIMEOUT_SECONDS);

        string leftover;
        const string address = intercept(request, leftover);
        if (address.empty())
            continue;

        const int port = openConnection(address);
        if (port <= 0 || port > 65535) {
            LOG_WARN("server refused the relay request");
            continue;
        }

        shared_ptr<TcpClient> conn;
        try {
            conn = shared_ptr<TcpClient>(new TcpClient(serverIp, port));
        } catch (const runtime_error &e) {
            LOG_WARN("cannot reach the relay port: %s", e.what());
            continue;
        }

        const auto passive = make_shared<PassiveSocket>();
        const auto channel = make_shared<ocelot::PassiveOcelotChannel>(aes);
        passive->copyTo(channel);
        channel->copyTo(passive);
        PassiveSocket::link(passive, channel);
        // Queued before registration; the loop flushes it as soon as the
        // socket joins the event loop.
        if (!leftover.empty())
            channel->write(leftover.data(), static_cast<int>(leftover.size()));
        epoll->registerSocket(request->release(), passive);
        epoll->registerSocket(conn->release(), channel);
    }
}
