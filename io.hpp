#ifndef _IO_HPP_
#define _IO_HPP_

#include "unisocket.hpp"
#include <atomic>
#include <future>
#include <map>
#include <queue>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#define SOCKET_ERROR (-1)

#ifdef _WIN32
#include "wepoll.h"
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
#define HANDLE int
#define closesocket(x) ::close(x)
#define epoll_close(x) ::close(x)
#endif

namespace io {
using namespace std;
using namespace unisocket;
class SocketStream {
    queue<pair<size_t, function<void(void*)>>> que;

public:
    template <typename T>
    void read(function<void(T)>& func)
    {
        que.push(make_pair(sizeof(T), [&](void* mem) {
            T* val = mem;
            func(*val);
        }));
    }
};

class Epoll {
    HANDLE epoll_fd;
    atomic_int conn;
    thread th;
    map<SOCKET, function<void(TcpClient&)>> mp;

public:
    Epoll()
    {
        epoll_fd = epoll_create1(0);
    }

    void registerSocket(TcpClient& socket, function<void(TcpClient&)> func)
    {
        epoll_event event;
        event.events = { EPOLLIN };
        event.data.fd = socket.getFD();
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket.getFD(), &event) == -1) {
            cerr << "epoll_ctl failed" << endl;
            socket.close();
            epoll_close(epoll_fd);
            return;
        }
        mp[socket.getFD()] = func;
        if (!conn) {
            th = thread([&]() {
                while (conn) {
                    vector<epoll_event> events(conn);
                    if (int r = epoll_wait(epoll_fd, events.data(), conn, 0)) {
                        if (r == -1) {
                            cerr << "epoll_wait failed" << endl;
                            epoll_close(epoll_fd);
                        }
                        for (int i = 0; i < r; i++) {
                            TcpClient client(events[i].data.fd);
                            if (events[i].events & EPOLLHUP) {
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client.getFD(), NULL);
                                client.close();
                            }
                            if (events[i].events & EPOLLIN) {
                                mp[events[i].data.fd](client);
                            }
                        }
                    }
                }
            });
        }
        ++conn;
    }

    void unregisterSocket(TcpClient& socket)
    {
        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket.getFD(), NULL) == -1) {
            cerr << "epoll_ctl failed" << endl;
            socket.close();
            epoll_close(epoll_fd);
        }
    }

    void close()
    {
        for (auto p : mp) {
            closesocket(p.first);
        }
        conn = 0;
        epoll_close(epoll_fd);
        if (th.joinable())
            th.join();
    }
};
}

#endif