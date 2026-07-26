#ifndef OCELOT_UNISOCKET_HPP
#define OCELOT_UNISOCKET_HPP

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "logging.hpp"

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SOCKET int
#define INVALID_SOCKET (-1)
#define closesocket(x) ::close(x)
#endif

namespace unisocket {
    inline bool initialized = false;

    inline int getErrorCode() {
#ifdef _WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }

    /// True when the last operation failed only because the socket is
    /// non-blocking and had nothing to give / no room to take.
    inline bool wouldBlock() {
        const int e = getErrorCode();
#ifdef _WIN32
        return e == WSAEWOULDBLOCK || e == WSAEINTR;
#else
        return e == EAGAIN || e == EWOULDBLOCK || e == EINTR;
#endif
    }

    /// True when a non-blocking connect() has been started but not finished.
    inline bool connectInProgress() {
        const int e = getErrorCode();
#ifdef _WIN32
        return e == WSAEWOULDBLOCK;
#else
        return e == EINPROGRESS || e == EINTR;
#endif
    }

    inline void init() {
        if (initialized)
            return;
        initialized = true;
#ifdef _WIN32
        WORD sockVersion = MAKEWORD(2, 2);
        WSADATA wsaData;
        if (WSAStartup(sockVersion, &wsaData)) {
            throw std::runtime_error("Cannot startup WSA!");
        }
#else
        // Without this a single peer that disappears mid-transfer kills the
        // whole proxy: send() on a reset connection raises SIGPIPE, whose
        // default disposition is to terminate the process.
        signal(SIGPIPE, SIG_IGN);
#endif
    }

    inline bool setNonBlocking(const SOCKET fd) {
#ifdef _WIN32
        u_long mode = 1;
        return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1)
            return false;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
#endif
    }

    /// TCP_NODELAY takes an `int`.  The old helper passed a 1-byte `bool`, so
    /// the kernel rejected it with EINVAL and every relayed segment could pay a
    /// Nagle delay on top of the real round trip.
    inline bool setNoDelay(const SOCKET fd, const bool nodelay = true) {
        int flag = nodelay ? 1 : 0;
        return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&flag),
                          sizeof(flag)) != SOCKET_ERROR;
    }

    inline bool setKeepAlive(const SOCKET fd, const bool on = true) {
        int flag = on ? 1 : 0;
        return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char *>(&flag),
                          sizeof(flag)) != SOCKET_ERROR;
    }

    constexpr int BACKLOG = 1024;
    constexpr int BUFFER_SIZE = 16384;

#ifdef MSG_NOSIGNAL
    constexpr int SEND_FLAGS = MSG_NOSIGNAL;
#else
    constexpr int SEND_FLAGS = 0;
#endif

    // ---------------------------------------------------------------- DNS ---
    // getaddrinfo() is a blocking call and the relay runs it from the epoll
    // thread, so one slow lookup stalls every other tunnel sharing that thread.
    // A short-lived cache removes the lookup entirely for repeat destinations,
    // which is the overwhelmingly common case for a browser proxy.
    constexpr int DNS_TTL_SECONDS = 60;
    constexpr size_t DNS_CACHE_MAX = 4096;

    inline std::mutex &dnsMutex() {
        static std::mutex m;
        return m;
    }

    using DnsEntry = std::pair<uint32_t, std::chrono::steady_clock::time_point>;

    inline std::unordered_map<std::string, DnsEntry> &dnsCache() {
        static std::unordered_map<std::string, DnsEntry> c;
        return c;
    }

    /// Resolves `host` to a network-order IPv4 address.  Literal addresses skip
    /// the resolver entirely.
    inline bool resolveHost(const std::string &host, uint32_t &out) {
        in_addr literal{};
        if (inet_pton(AF_INET, host.c_str(), &literal) == 1) {
            out = literal.s_addr;
            return true;
        }

        const auto now = std::chrono::steady_clock::now(); {
            std::lock_guard<std::mutex> lk(dnsMutex());
            const auto it = dnsCache().find(host);
            if (it != dnsCache().end() && it->second.second > now) {
                out = it->second.first;
                return true;
            }
        }

        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr)
            return false;
        out = reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res); {
            std::lock_guard<std::mutex> lk(dnsMutex());
            if (dnsCache().size() >= DNS_CACHE_MAX)
                dnsCache().clear();
            dnsCache()[host] = {out, now + std::chrono::seconds(DNS_TTL_SECONDS)};
        }
        return true;
    }

    class NetworkStream {
    public:
        virtual ~NetworkStream() = default;

        NetworkStream() { init(); }

        virtual int Input(std::string &buf) = 0;

        virtual bool Output(std::string &buf) = 0;

        virtual bool isClosed() = 0;
    };

    class TcpClient : public NetworkStream {
        SOCKET socket_fd = INVALID_SOCKET;
        sockaddr_in addr{};
        bool closed = false;

    public:
        TcpClient() { closed = true; }

        TcpClient(const SOCKET socket_fd, const sockaddr_in addr) : socket_fd(socket_fd), addr(addr) {}

        explicit TcpClient(const SOCKET socket_fd) : socket_fd(socket_fd) {}

        TcpClient(const TcpClient &clone) = delete;

        TcpClient &operator=(const TcpClient &clone) = delete;

        /// Owns its descriptor.  Error paths used to drop TcpClient objects on
        /// the floor and leak the fd; hand the descriptor to release() when
        /// something else (the epoll loop) takes over.
        ~TcpClient() override { close(); }

        /// Blocking connect.  Used for the client's long-lived control link,
        /// where there is nothing else to do until it completes.
        TcpClient(const std::string &ip, const int port) {
            init();
            uint32_t resolved;
            if (!resolveHost(ip, resolved))
                throw std::runtime_error("Cannot resolve " + ip);

            socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (socket_fd == INVALID_SOCKET)
                throw std::runtime_error("Cannot create socket");

            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            serverAddr.sin_addr.s_addr = resolved;

            if (::connect(socket_fd, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
                close();
                throw std::runtime_error("Cannot connect to " + ip + ":" + std::to_string(port));
            }
            addr = serverAddr;
            unisocket::setNoDelay(socket_fd);
        }

        /// Starts a connect without waiting for the handshake to finish.  The
        /// socket becomes writable once the SYN/ACK lands (or reports the
        /// failure through EPOLLERR), so the caller's event loop is never
        /// blocked by a slow or unreachable destination.
        static TcpClient *connectAsync(const std::string &ip, const int port) {
            init();
            uint32_t resolved;
            if (!resolveHost(ip, resolved))
                throw std::runtime_error("Cannot resolve " + ip);

            const SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (fd == INVALID_SOCKET)
                throw std::runtime_error("Cannot create socket");

            setNonBlocking(fd);
            unisocket::setNoDelay(fd);

            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            serverAddr.sin_addr.s_addr = resolved;

            if (::connect(fd, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR
                && !connectInProgress()) {
                closesocket(fd);
                throw std::runtime_error("Cannot connect to " + ip + ":" + std::to_string(port));
            }
            return new TcpClient(fd, serverAddr);
        }

        SOCKET getFD() const { return socket_fd; }

        void setSendTimeout(const int timeout = 5) const {
            timeval tv{};
            tv.tv_sec = timeout;
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char *>(&tv), sizeof(tv));
        }

        void setRecvTimeout(const int timeout = 5) const {
            timeval tv{};
            tv.tv_sec = timeout;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&tv), sizeof(tv));
        }

        bool setNoDelay(const bool nodelay = true) const { return unisocket::setNoDelay(socket_fd, nodelay); }

        // --- blocking helpers, used only for the short synchronous handshakes ---

        /// Reads exactly `len` bytes.  The previous implementation added the
        /// return value of a failed recv() (-1) to its progress counters, which
        /// silently corrupted the remaining-byte arithmetic.
        bool readFully(char *buf, const size_t len) {
            size_t got = 0;
            while (got < len) {
                const int r = recv(socket_fd, buf + got, len - got, 0);
                if (r > 0) {
                    got += static_cast<size_t>(r);
                    continue;
                }
                if (r < 0 && getErrorCode() == EINTR)
                    continue;
                close();
                return false;
            }
            return true;
        }

        bool writeFully(const char *buf, const size_t len) {
            size_t sent = 0;
            while (sent < len) {
                const int r = send(socket_fd, buf + sent, len - sent, SEND_FLAGS);
                if (r > 0) {
                    sent += static_cast<size_t>(r);
                    continue;
                }
                if (r < 0 && getErrorCode() == EINTR)
                    continue;
                close();
                return false;
            }
            return true;
        }

        template<typename T>
        int read(T *val) {
            return readFully(reinterpret_cast<char *>(val), sizeof(T)) ? static_cast<int>(sizeof(T)) : 0;
        }

        template<typename T>
        int read(T &val) { return read(&val); }

        /// Reads a 32-bit length prefix followed by that many bytes.
        int read(std::string &str) {
            uint32_t len = 0;
            if (!read(&len))
                return 0;
            if (len > (1u << 24)) {
                close();
                return 0;
            }
            str.resize(len);
            if (len && !readFully(str.data(), len))
                return 0;
            return static_cast<int>(len);
        }

        int read(std::string &str, const int len) {
            if (len <= 0)
                return 0;
            str.resize(len);
            return readFully(str.data(), len) ? len : 0;
        }

        int receive(char *buf, const int pos, const int size) const {
            return recv(socket_fd, buf + pos, size, 0);
        }

        template<typename T>
        bool write(T *val) { return writeFully(reinterpret_cast<const char *>(val), sizeof(T)); }

        template<typename T>
        bool write(T &&val) { return write(&val); }

        bool write(const char *buf, const int len) {
            return len <= 0 ? true : writeFully(buf, static_cast<size_t>(len));
        }

        bool write(std::string &str, const int len) { return write(str.data(), len); }

        int Input(std::string &buf) override {
            buf.resize(BUFFER_SIZE);
            const int ret = recv(socket_fd, buf.data(), BUFFER_SIZE, 0);
            buf.resize(ret > 0 ? ret : 0);
            return ret;
        }

        bool Output(std::string &buf) override { return write(buf.data(), static_cast<int>(buf.size())); }

        void close() {
            if (!closed && socket_fd != INVALID_SOCKET)
                closesocket(socket_fd);
            closed = true;
        }

        /// Hands ownership of the descriptor to someone else (the epoll loop),
        /// so this wrapper going out of scope cannot close a live socket.
        SOCKET release() {
            const SOCKET fd = socket_fd;
            socket_fd = INVALID_SOCKET;
            closed = true;
            return fd;
        }

        bool isClosed() override { return closed; }
    };

    inline void copyTo(NetworkStream *src, NetworkStream *dest) {
        std::string buf;
        while (!dest->isClosed() && !src->isClosed() && src->Input(buf) > 0) {
            if (!dest->Output(buf))
                break;
            buf.clear();
        }
    }

    class TcpServer {
    protected:
        SOCKET socket_fd;
        bool closed = false;
        sockaddr_in server_addr{};

    public:
        explicit TcpServer(const SOCKET socket) : socket_fd(socket) {}

        TcpServer(const std::string &ip, const int port, const int backlog = BACKLOG) {
            init();
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            server_addr.sin_addr.s_addr = inet_addr(ip.c_str());

            socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (socket_fd == INVALID_SOCKET)
                throw std::runtime_error("Can't open socket port");

            int on = 1;
            if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&on),
                           sizeof(on)) == SOCKET_ERROR)
                throw std::runtime_error("Can't setsockopt");

            if (bind(socket_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR)
                throw std::runtime_error("bind error");

            if (listen(socket_fd, backlog) == SOCKET_ERROR)
                throw std::runtime_error("listen error");
        }

        SOCKET getFD() const { return socket_fd; }

        int getPort() const {
            sockaddr_in sin{};
            socklen_t len = sizeof(sin);
            if (getsockname(socket_fd, reinterpret_cast<sockaddr *>(&sin), &len) == SOCKET_ERROR)
                throw std::runtime_error("getsockname error");
            return ntohs(sin.sin_port);
        }

        /// Returns nullptr instead of throwing when there is nothing to accept.
        ///
        /// The old version unconditionally applied SO_LINGER with a 4-byte
        /// `int`, but the option takes an 8-byte `struct linger`; the kernel
        /// rejected it with EINVAL and the resulting throw aborted *every*
        /// accept.  SO_LINGER is not wanted here anyway -- it either blocks
        /// close() or turns it into an RST that truncates in-flight data.
        TcpClient *accept() const {
            sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(sockaddr_in);
            const SOCKET s_client = ::accept(socket_fd, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
            if (s_client == INVALID_SOCKET)
                return nullptr;
            setNoDelay(s_client);
            return new TcpClient(s_client, client_addr);
        }

        void close() {
            if (!closed)
                closesocket(socket_fd);
            closed = true;
        }
    };
}

#endif
