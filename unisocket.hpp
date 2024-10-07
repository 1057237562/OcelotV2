#ifndef _UNISOCKET_HPP_
#define _UNISOCKET_HPP_

#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <cstdio>
#include <string>
#include <vector>
#define SOCKET_ERROR (-1)

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SOCKET int
#define closesocket(x) ::close(x)
#endif

#define endl '\n'

namespace unisocket {
    static bool initialized = false;

    inline void init() {
        if (!initialized) {
            initialized = true;
#ifdef _WIN32
            WORD sockVersion = MAKEWORD(2, 2);
            WSADATA wsaData;

            if (WSAStartup(sockVersion, &wsaData)) {
                throw std::runtime_error("Cannot startup WSA!");
            }
#endif
        }
    }

    inline int getErrorCode() {
#ifdef _WIN32
        return WSAGetLastError();
#else
    return errno;
#endif
    }

    constexpr int BACKLOG = 1024;
    constexpr int BUFFER_SIZE = 1500; // Default MTU size

    class NetworkStream {
    public:
        virtual ~NetworkStream() = default;

        NetworkStream() { init(); }

        virtual int Input(std::string &buf) = 0;

        virtual bool Output(std::string &buf) = 0;

        virtual bool isClosed() = 0;
    };

    inline void copyTo(NetworkStream *src, NetworkStream *dest) {
        std::string buf;
        while (!dest->isClosed() && !src->isClosed() && src->Input(buf)) {
            if (!dest->Output(buf))
                break;
            buf.clear();
        }
    }

    class TcpClient : public NetworkStream {
        SOCKET socket_fd{};
        sockaddr_in addr{};
        bool closed = false;

    public:
        TcpClient() { closed = true; }

        TcpClient(const SOCKET socket_fd, const sockaddr_in addr) {
            this->socket_fd = socket_fd;
            this->addr = addr;
        }

        TcpClient(const SOCKET socket_fd) {
            this->socket_fd = socket_fd;
        }

        TcpClient(const TcpClient &clone) = delete;

        TcpClient &operator=(const TcpClient &clone) = delete;

        SOCKET getFD() const { return socket_fd; }

        void setSendTimeout(const int timeout = 5) const {
            timeval tv{};
            tv.tv_sec = timeout;
            tv.tv_usec = 0;
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char *>(&tv), sizeof(tv));
        }

        void setRecvTimeout(const int timeout = 5) const {
            timeval tv{};
            tv.tv_sec = timeout;
            tv.tv_usec = 0;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&tv), sizeof(tv));
        }

        TcpClient(const std::string &ip, const int port) {
            socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());

            addrinfo hints{}, *res;
            memset(&hints, 0, sizeof(addrinfo));
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_family = AF_INET;

            if (!getaddrinfo(ip.c_str(), nullptr, &hints, &res)) {
                serverAddr.sin_addr.s_addr = reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr.s_addr;
                freeaddrinfo(res);
            }

            if (connect(socket_fd, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
                std::cerr << "Cannot connect to " + ip + ":" + std::to_string(port) << endl;;
                close();
                throw std::runtime_error("Connect error !");
            }
        }

        bool setNoDelay(bool nodelay) const {
            int ret = setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&nodelay),
                                 sizeof(nodelay));
            return ret != SOCKET_ERROR;
        }

        template<typename T>
        int read(T *val) {
            size_t bufsize = sizeof(T), ptr = 0;
            char buf[bufsize];
            int ret = recv(socket_fd, buf, bufsize, 0);
            ptr += ret;
            bufsize -= ret;
            while (bufsize) {
                if (ret <= 0) {
                    close();
                    return 0;
                }
                ret = recv(socket_fd, buf + ptr, bufsize, 0);
                ptr += ret;
                bufsize -= ret;
            }
            memcpy(val, buf, ptr);
            return ptr;
        }

        template<typename T>
        int read(T &val) {
            return read(&val);
        }

        int read(std::string &str) {
            int bufsize, ptr = 0;
            if (!read(&bufsize))
                return false;
            str.resize(std::min(bufsize, BUFFER_SIZE));
            int ret = recv(socket_fd, const_cast<char *>(str.data()), std::min(bufsize, BUFFER_SIZE), 0);
            ptr += ret;
            bufsize -= ret;
            while (bufsize) {
                if (ret <= 0) {
                    close();
                    return 0;
                }
                str.resize(str.size() + std::min(bufsize, BUFFER_SIZE));
                ret = recv(socket_fd, const_cast<char *>(str.data()) + ptr, std::min(bufsize, BUFFER_SIZE), 0);
                ptr += ret;
                bufsize -= ret;
            }
            return ptr;
        }

        int read(std::string &str, int len) {
            if (!len)
                return true;
            int bufsize = len, ptr = 0;
            char buf[bufsize];
            int ret = recv(socket_fd, buf, bufsize, 0);
            ptr += ret;
            bufsize -= ret;
            while (bufsize) {
                if (ret <= 0) {
                    close();
                    return 0;
                }
                ret = recv(socket_fd, buf + ptr, bufsize, 0);
                ptr += ret;
                bufsize -= ret;
            }
            str = std::string(buf, ptr);
            return ptr;
        }

        template<typename T>
        bool write(T *val) {
            int bufsize = sizeof(T), ptr = 0;
            int ret = send(socket_fd, reinterpret_cast<const char *>(val), bufsize, 0);
            bufsize -= ret;
            ptr += ret;
            while (bufsize) {
                if (ret <= 0) {
                    close();
                    return false;
                }
                ret = send(socket_fd, reinterpret_cast<const char *>(val) + ptr, bufsize, 0);
                bufsize -= ret;
                ptr += ret;
            }
            return true;
        }

        template<typename T>
        bool write(T &val) {
            return write(&val);
        }

        bool write(char *buf, int len) {
            if (!len)
                return true;
            int bufsize = len, ptr = 0;
            int ret = send(socket_fd, buf, bufsize, 0);
            bufsize -= ret;
            ptr += ret;
            while (bufsize) {
                if (ret <= 0) {
                    close();
                    return false;
                }
                ret = send(socket_fd, buf + ptr, bufsize, 0);
                bufsize -= ret;
                ptr += ret;
            }
            return true;
        }

        bool write(std::string &str, const int len) {
            return write(str.data(), len);
        }

        int Input(std::string &buf) override {
            buf.resize(BUFFER_SIZE);
            int ret = recv(socket_fd, const_cast<char *>(buf.data()), BUFFER_SIZE, 0);
            buf.resize(ret);
            return ret;
        }

        bool Output(std::string &buf) override {
            return write(buf.data(), buf.size());
        }

        void close() {
            if (!closed) {
                closesocket(socket_fd);
            }
            closed = true;
        }

        bool isClosed() override {
            return closed;
        }
    };

    class TcpServer {
    protected:
        SOCKET socket_fd;
        bool closed = false;
        sockaddr_in server_addr{};

    public:
        TcpServer(const std::string &ip, const int port, const int backlog = BACKLOG) {
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            server_addr.sin_addr.s_addr = inet_addr(ip.c_str());

            socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

            if (socket_fd == -1) {
                throw std::runtime_error("Can't open socket port");
            }

            int on = 1;
            if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&on),
                           sizeof(on)) == -1) {
                throw std::runtime_error("Can't setsockopt");
            }

            int bind_result = bind(socket_fd, reinterpret_cast<struct sockaddr *>(&server_addr), sizeof(server_addr));

            if (bind_result == -1) {
                throw std::runtime_error("bind error");
            }

            if (listen(socket_fd, backlog) == SOCKET_ERROR) {
                throw std::runtime_error("listen error");
            }
        }

        SOCKET getFD() const {
            return socket_fd;
        }

        int getPort() const {
            sockaddr_in sin{};
            socklen_t len = sizeof(sin);
            if (getsockname(socket_fd, reinterpret_cast<sockaddr *>(&sin), &len) == -1) {
                throw std::runtime_error("getsockname error");
            }
            return ntohs(sin.sin_port);
        }

        TcpClient *accept(int timeout = 0) const {
            if (timeout) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(socket_fd, &fds);
                timeval tv{};
                tv.tv_sec = timeout;
                tv.tv_usec = 0;
                int ret = select(socket_fd + 1, &fds, nullptr, nullptr, &tv);
                if (ret == 0) {
                    return nullptr;
                }
                if (ret == -1) {
                    throw std::runtime_error("select error");
                }
            }

            sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(sockaddr_in);
            SOCKET s_client = ::accept(socket_fd, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);

            int on = 1;
            if (setsockopt(s_client, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char *>(&on),
                           sizeof(on)) == -1) {
                throw std::runtime_error("Can't setsockopt");
            }
            return new TcpClient(s_client, client_addr);
        }

        void close() {
            if (!closed) {
                closesocket(socket_fd);
            }
            closed = true;
        }
    };
}
#endif
