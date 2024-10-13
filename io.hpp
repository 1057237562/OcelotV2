#ifndef _IO_HPP_
#define _IO_HPP_

#include "unisocket.hpp"
#include <atomic>
#include <cassert>
#include <future>
#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
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

#define FD_MAX 65536
#define MTU 1500
#define endl '\n'

namespace io {
    class Epoll;
    using namespace std;
    using namespace unisocket;

    class PassiveSocket {
    protected:
        string rd_buffer;
        string wr_buffer;
        size_t ptr = 0;
        queue<pair<size_t, function<void(char *, int, SOCKET, PassiveSocket *)> > > que;

    public:
        PassiveSocket() = default;

        virtual ~PassiveSocket() {
            cout << "Passive Socket deleted " << this << endl;
        }

        template<typename T>
        void read(function<void(T, SOCKET)> func) {
            que.emplace(sizeof(T), [=](char *buf, int, SOCKET socket, PassiveSocket *) {
                T *val = (T *) buf;
                func(*val, socket);
            });
            if (rd_buffer.empty()) {
                rd_buffer.resize(sizeof(T));
                ptr = 0;
            }
        }

        template<typename T>
        void read(function<void(T, SOCKET, PassiveSocket *)> func) {
            que.emplace(sizeof(T), [=](char *buf, int, SOCKET socket, PassiveSocket *current) {
                T *val = (T *) buf;
                func(*val, socket, current);
            });
            if (rd_buffer.empty()) {
                rd_buffer.resize(sizeof(T));
                ptr = 0;
            }
        }

        template<typename T>
        void read(T *val) {
            que.emplace(sizeof(T), [=, this](char *buf, int, SOCKET) {
                memcpy(val, static_cast<T *>(buf), sizeof(T));
            });
            if (rd_buffer.empty()) {
                rd_buffer.resize(sizeof(T));
                ptr = 0;
            }
        }

        virtual void write(const char *buf, const int len) {
            wr_buffer.append(buf, len);
        }

        template<typename T>
        void write(T *val) {
            write((char *) val, sizeof(T));
        }

        template<typename T>
        void write(T &val) {
            return write(&val);
        }

        virtual void copyTo(const shared_ptr<PassiveSocket> &target) {
            while (!que.empty())
                que.pop();
            que.emplace(-1, [=](char *buf, int len, SOCKET, PassiveSocket *) {
                target->write(buf, len);
            });
            if (rd_buffer.empty()) {
                rd_buffer.resize(MTU);
                ptr = 0;
            }
        }

        virtual int recvData(SOCKET socket) {
            int r = 0;
            if ((r = recv(socket, rd_buffer.data() + ptr, rd_buffer.size() - ptr, 0)) > 0) {
                ptr += r;
                auto top = que.front();
                if (ptr == rd_buffer.size()) {
                    que.pop();
                    top.second(rd_buffer.data(), static_cast<int>(ptr), socket, this);
                    if (!que.empty()) {
                        top = que.front();
                        rd_buffer.resize(top.first);
                        ptr = 0;
                    }
                }
                if (top.first < 0 && ptr >= -top.first) {
                    size_t len = ptr - ptr % -top.first;
                    top.second(rd_buffer.data(), static_cast<int>(len), socket, this);
                    rd_buffer = rd_buffer.substr(len);
                    ptr %= -top.first;
                }
            }
            return r;
        }

        virtual int sendData(SOCKET socket) {
            int r = 0;
            if (wr_buffer.empty()) return 0;
            if ((r = send(socket, wr_buffer.data(), wr_buffer.size(), 0)) > 0) {
                wr_buffer = wr_buffer.substr(r);
            }
            return r;
        }

        bool empty() const {
            return wr_buffer.empty();
        }
    };

    class PassiveServer : public PassiveSocket {
    protected:
        function<void(shared_ptr<TcpClient>)> func;

    public:
        explicit PassiveServer(function<void(shared_ptr<TcpClient>)> proc) : func(std::move(proc)) {}

        int recvData(SOCKET socket) override {
            const TcpServer server(socket);
            func(shared_ptr<TcpClient>(server.accept()));
            return 1;
        }
    };

    class Epoll {
    protected:
        HANDLE epoll_fd;
        atomic_int conn{};
        thread th;
        shared_ptr<PassiveSocket> mp[FD_MAX];
        epoll_event events[1024]{};
        uint32_t mode;

    public:
        explicit Epoll(uint32_t mode = EPOLLIN) : mode(mode) {
            epoll_fd = epoll_create1(0);
            conn = 0;
        }

        ~Epoll() {
            epoll_close(epoll_fd);
            if (th.joinable())
                th.join();
        }

        void modifySocket(SOCKET socket_fd, const uint32_t m) const {
            epoll_event event{};
            event.events = m;
            event.data.fd = socket_fd;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, socket_fd, &event) == -1) {
                cerr << "epoll_ctl failed" << endl;
                closesocket(socket_fd);
                epoll_close(epoll_fd);
            }
        }

        void syncEpollThread() {
            if (th.joinable())
                th.join();
            th = thread([&]() {
                while (conn) {
                    cout << "Incoming Transmission " << conn << endl;
                    if (int r = epoll_wait(epoll_fd, events, 1024, -1)) {
                        if (r == -1) {
                            cerr << "epoll_wait failed" << endl;
                            close();
                        }
                        for (int i = 0; i < r; i++) {
                            TcpClient client(events[i].data.fd);
                            shared_ptr<PassiveSocket> current = mp[events[i].data.fd];
                            if (current == nullptr) {
                                unregisterSocket(client);
                                continue;
                            }
                            if (events[i].events & EPOLLIN) {
                                if (current->recvData(events[i].data.fd) == 0) {
                                    unregisterSocket(client);
                                }
                                if (!current->empty()) {
                                    modifySocket(events[i].data.fd, EPOLLOUT);
                                }
                            }
                            if (events[i].events & EPOLLOUT) {
                                if (current->sendData(events[i].data.fd) == 0) {
                                    modifySocket(events[i].data.fd, mode);
                                }
                            }
                            if (events[i].events & EPOLLHUP) {
                                while (!current->recvData(events[i].data.fd)) {}
                                unregisterSocket(client);
                            }
                        }
                    }
                }
                cout << "Epoll thread exit" << endl;
            });
        }

        void registerSocket(const shared_ptr<TcpClient> &socket, const shared_ptr<PassiveSocket> &passive) {
            mp[socket->getFD()] = passive;
            epoll_event event{};
            event.events = mode;
            event.data.fd = socket->getFD();
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket->getFD(), &event) == -1) {
                cerr << "epoll_ctl failed" << endl;
                socket->close();
                epoll_close(epoll_fd);
                return;
            }
            if (!conn++) {
                syncEpollThread();
            }
        }

        void unregisterSocket(TcpClient &socket) {
            cout << "Connection closed" << endl;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket.getFD(), nullptr) == -1) {
                cerr << "epoll_ctl failed" << endl;
                epoll_close(epoll_fd);
            }
            socket.close();
            if (mp[socket.getFD()] != nullptr) {
                mp[socket.getFD()].reset();
            }
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
