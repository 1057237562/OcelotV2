#ifndef _IO_HPP_
#define _IO_HPP_

#include "unisocket.hpp"
#include <atomic>
#include <future>
#include <map>
#include <queue>
#include <mutex>
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

    class PassiveSocket {
        vector<char> buffer;
        size_t ptr = 0;
        queue<pair<size_t, function<void(void *, SOCKET)> > > que;

    public:
        template<typename T>
        void read(function<void(T, SOCKET)> func) {
            que.push(make_pair(sizeof(T), [=](void *mem, SOCKET socket) {
                T *val = static_cast<T *>(mem);
                func(*val, socket);
            }));
            if (buffer.empty()) {
                buffer.resize(sizeof(T));
                ptr = 0;
            }
        }

        int recvData(SOCKET socket) {
            int r;
            if ((r = recv(socket, buffer.data() + ptr, buffer.size() - ptr, 0)) > 0) {
                ptr += r;
                if (ptr == buffer.size()) {
                    auto top = que.front();
                    que.pop();
                    top.second(buffer.data(), socket);
                    if (!que.empty()) {
                        top = que.front();
                        buffer.resize(top.first);
                        ptr = 0;
                    }
                }
            }
            return r;
        }
    };

    class Epoll {
        HANDLE epoll_fd;
        atomic_int conn;
        thread th;
        map<SOCKET, shared_ptr<PassiveSocket> > mp;
        pair<SOCKET, shared_ptr<PassiveSocket> > buffer[4096];
        epoll_event events[1024];
        int limit;
        int ptr;

    public:
        Epoll() {
            epoll_fd = epoll_create1(0);
            conn = limit = ptr = 0;
        }

        ~Epoll() {
            epoll_close(epoll_fd);
            if (th.joinable())
                th.join();
        }

        void registerSocket(const shared_ptr<TcpClient> &socket, const shared_ptr<PassiveSocket> &passive) {
            buffer[limit++] = make_pair(socket->getFD(), shared_ptr<PassiveSocket>(passive));
            limit %= 4096;
            epoll_event event{};
            event.events = {EPOLLIN};
            event.data.fd = socket->getFD();
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket->getFD(), &event) == -1) {
                cerr << "epoll_ctl failed" << endl;
                socket->close();
                epoll_close(epoll_fd);
                return;
            }
            if (!conn++) {
                if (th.joinable())
                    th.join();
                th = thread([&]() {
                    while (conn) {
                        cout << "Incoming Transmission " << mp.size() << endl;
                        while (limit != ptr) {
                            mp.insert(buffer[ptr++]);
                            ptr %= 4096;
                        }
                        if (int r = epoll_wait(epoll_fd, events, 1024, -1)) {
                            if (r == -1) {
                                cerr << "epoll_wait failed" << endl;
                                close();
                            }
                            for (int i = 0; i < r; i++) {
                                TcpClient client(events[i].data.fd);
                                if (events[i].events & EPOLLHUP) {
                                    unregisterSocket(client);
                                }
                                if (events[i].events & EPOLLIN) {
                                    if (mp[events[i].data.fd].get() != nullptr) {
                                        if (mp[events[i].data.fd]->recvData(events[i].data.fd) == 0) {
                                            unregisterSocket(client);
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }
            ++conn;
        }

        void unregisterSocket(TcpClient &socket) {
            cout << "Connection closed" << endl;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket.getFD(), NULL) == -1) {
                cerr << "epoll_ctl failed" << endl;
                epoll_close(epoll_fd);
            }
            socket.close();
            mp.erase(socket.getFD());
            --conn;
        }

        void close() {
            conn = 0;
            epoll_close(epoll_fd);
            if (th.joinable())
                th.join();
        }
    };
}

#endif
