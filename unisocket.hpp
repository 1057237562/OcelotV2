#ifndef _UNISOCKET_HPP_
#define _UNISOCKET_HPP_

#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <string>
#define SOCKET_ERROR (-1)

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
namespace unisocket {
inline void init()
{
    WORD sockVersion = MAKEWORD(2, 2);
    WSADATA wsaData;

    if (WSAStartup(sockVersion, &wsaData)) {
        throw std::runtime_error("Cannot startup WSA!");
        return;
    }
}
}
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SOCKET int
#define closesocket(x) ::close(x)
#endif
namespace unisocket {
const int BACKLOG = 2;
const int BUFFER_SIZE = 1500; // Default MTU size

class Stream {
public:
    virtual int Input(std::string& buf) const = 0;
    virtual void Output(std::string& buf) const = 0;
    virtual bool isClosed() = 0;
};

inline void copyTo(Stream* src, Stream* dest)
{
    std::string buf;
    while (!dest->isClosed() && src->Input(buf)) {
        dest->Output(buf);
        buf.clear();
    }
}

class TcpClient : public Stream {
    SOCKET socket_fd;
    sockaddr_in addr;
    bool closed = false;

public:
    TcpClient(SOCKET socket_fd, sockaddr_in addr)
    {
        this->socket_fd = socket_fd;
        this->addr = addr;
    }

    TcpClient(const std::string ip, const int port)
    {
        socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());

        addrinfo hints, *res;
        memset(&hints, 0, sizeof(addrinfo));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_INET;

        if (!getaddrinfo(ip.c_str(), NULL, &hints, &res)) {
            serverAddr.sin_addr.s_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
            freeaddrinfo(res);
        }

        if (connect(socket_fd, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cout << "Cannot connect to " + ip + ":" + std::to_string(port) << std::endl;
            closesocket(socket_fd);
            throw std::runtime_error("Connect error !");
            return;
        }
    }

    bool setNoDelay(bool nodelay)
    {
        int ret = setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
        return ret != SOCKET_ERROR;
    }

    template <typename T>
    int read(T* val) const
    {
        size_t bufsize = sizeof(T), ptr = 0;
        char buf[bufsize];
        int ret = recv(socket_fd, buf, bufsize, 0);
        ptr += ret;
        bufsize -= ret;
        while (bufsize) {
            if (!ret) {
                return 0;
            }
            ret = recv(socket_fd, buf + ptr, bufsize, 0);
            ptr += ret;
            bufsize -= ret;
        }
        memcpy(val, buf, ptr);
        return ptr;
    }

    int read(std::string& str) const
    {
        int bufsize, ptr = 0;
        if (!read(&bufsize))
            return false;
        char buf[bufsize];
        int ret = recv(socket_fd, buf, bufsize, 0);
        ptr += ret;
        bufsize -= ret;
        while (bufsize) {
            if (!ret) {
                return 0;
            }
            ret = recv(socket_fd, buf + ptr, bufsize, 0);
            ptr += ret;
            bufsize -= ret;
        }
        str = std::string(buf, ptr);
        return ptr;
    }

    int read(std::string& str, int len) const
    {
        int bufsize = len, ptr = 0;
        char buf[bufsize];
        int ret = recv(socket_fd, buf, bufsize, 0);
        ptr += ret;
        bufsize -= ret;
        while (bufsize) {
            if (!ret) {
                return 0;
            }
            ret = recv(socket_fd, buf + ptr, bufsize, 0);
            ptr += ret;
            bufsize -= ret;
        }
        str = std::string(buf, ptr);
        return ptr;
    }

    template <typename T>
    void write(T* val) const
    {
        send(socket_fd, (const char*)val, sizeof(T), 0);
    }

    void write(std::string& str, int len) const
    {
        send(socket_fd, str.c_str(), len, 0);
    }

    void write(std::string& str) const
    {
        int bufsize = str.size();
        write(&bufsize);
        send(socket_fd, str.c_str(), str.size(), 0);
    }

    int Input(std::string& buf) const override
    {
        buf.resize(BUFFER_SIZE);
        int ret = recv(socket_fd, buf.data(), BUFFER_SIZE, 0);
        buf.resize(ret);
        return ret;
    }

    void Output(std::string& buf) const override
    {
        send(socket_fd, buf.data(), buf.size(), 0);
    }

    void close()
    {
        if (!closed) {
            closesocket(socket_fd);
        }
        closed = true;
    }

    bool isClosed() override
    {
        return closed;
    }
};

class TcpServer {
protected:
    SOCKET socket_fd;
    bool closed = false;

public:
    TcpServer(const std::string ip, const int port)
    {
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_addr.sin_addr.s_addr = inet_addr(ip.c_str());

        socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (socket_fd == -1) {
            throw std::runtime_error("Can't open socket port");
            return;
        }

        int on = 1;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on)) == -1) { // 防止出现bind error的地址已被占用
            throw std::runtime_error("Can't setsockopt");
            return;
        }

        int bind_result = bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

        if (bind_result == -1) {
            throw std::runtime_error("bind error");
            return;
        }

        // listen
        if (listen(socket_fd, BACKLOG) == SOCKET_ERROR) {
            throw std::runtime_error("listen error");
            return;
        }
    }

    int getPort()
    {
        struct sockaddr_in sin;
        socklen_t len = sizeof(sin);
        if (getsockname(socket_fd, (struct sockaddr*)&sin, &len) == -1) {
            throw std::runtime_error("getsockname error");
            return -1;
        }
        return ntohs(sin.sin_port);
    }

    TcpClient accept() const
    {
        SOCKET s_client;
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(sockaddr_in);
        s_client = ::accept(socket_fd, (sockaddr*)&client_addr, &addr_len);
        return TcpClient(s_client, client_addr);
    }

    void close()
    {
        if (!closed) {
            closesocket(socket_fd);
        }
        closed = true;
    }
};
}
#endif