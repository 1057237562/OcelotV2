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
#define MTU 8192
#define endl '\n'

namespace io {
    class Epoll;
    using namespace std;
    using namespace unisocket;

    template<typename T>
    string convertBit(T &&val) {
        return move(string(reinterpret_cast<char *>(&val), sizeof(T)));
    }

    class PassiveSocket {
    protected:
        string rd_buffer;
        string wr_buffer;
        size_t ptr = 0;
        queue<pair<long long, function<void(char *, int, SOCKET, shared_ptr<PassiveSocket>)> > > que;
        vector<function<void(SOCKET, shared_ptr<PassiveSocket>)> > closing;

    public:
        HANDLE epoll_fd = nullptr;
        SOCKET socket_fd = 0;

        PassiveSocket() = default;

        virtual ~PassiveSocket() {
            cout << "Passive Socket deleted " << this << endl;
        }

        void close(const function<void(SOCKET, shared_ptr<PassiveSocket>)> &func) {
            closing.emplace_back(func);
        }

        template<typename T>
        void read(function<void(T, SOCKET, shared_ptr<PassiveSocket>)> func) {
            que.emplace(sizeof(T), [=](char *buf, int, SOCKET socket, shared_ptr<PassiveSocket> current) {
                T *val = (T *) buf;
                func(*val, socket, current);
            });
            if (rd_buffer.empty()) {
                rd_buffer.resize(sizeof(T));
            }
        }

        template<typename T>
        void read(T *val) {
            que.emplace(sizeof(T), [=](char *buf, int, SOCKET, shared_ptr<PassiveSocket>) {
                memcpy(val, static_cast<T *>(buf), sizeof(T));
            });
            if (rd_buffer.empty()) {
                rd_buffer.resize(sizeof(T));
            }
        }

        void read(int len, const function<void(char *, SOCKET, shared_ptr<PassiveSocket>)> &func) {
            que.emplace(len, [=](char *buf, int, const SOCKET socket, shared_ptr<PassiveSocket> current) {
                func(buf, socket, current);
            });
            if (rd_buffer.empty()) {
                rd_buffer.resize(len);
            }
        }

        virtual void write(const char *buf, const int len) {
            wr_buffer.append(buf, len);
            epoll_event event{};
            event.events = EPOLLOUT;
            event.data.fd = socket_fd;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, socket_fd, &event) == -1) {
                cerr << "epoll_ctl output failed code: " << getErrorCode() << endl;
            }
        }

        template<typename T>
        void write(T *val) {
            write(reinterpret_cast<char *>(val), sizeof(T));
        }

        template<typename T>
        void write(T &&val) {
            return write(&val);
        }

        virtual void copyTo(const shared_ptr<PassiveSocket> &target) {
            while (!que.empty())
                que.pop();
            que.emplace(-1, [target](const char *buf, const int len, SOCKET, const shared_ptr<PassiveSocket> &) {
                target->write(buf, len);
            });
            rd_buffer.resize(MTU);
        }

        virtual int recvData(const SOCKET socket, shared_ptr<PassiveSocket> &current) {
            int r = 0;
            if ((r = recv(socket, rd_buffer.data() + ptr, rd_buffer.size() - ptr, 0)) > 0) {
                ptr += r;
                if (auto top = que.front(); top.first > 0) {
                    if (ptr == rd_buffer.size()) {
                        top.second(rd_buffer.data(), static_cast<int>(ptr), socket, current);
                        que.pop();
                        if (!que.empty()) {
                            top = que.front();
                            rd_buffer.resize(top.first);
                            ptr = 0;
                        }
                    }
                } else {
                    if (ptr >= -top.first) {
                        const size_t len = ptr - ptr % -top.first;
                        top.second(rd_buffer.data(), static_cast<int>(len), socket, current);
                        rd_buffer = rd_buffer.erase(0, len);
                        rd_buffer.resize(MTU);
                        ptr %= -top.first;
                    }
                }
            }
            return r;
        }

        virtual int sendData(const SOCKET socket) {
            int r = 0;
            if (wr_buffer.empty()) return 0;
            if ((r = send(socket, wr_buffer.data(), wr_buffer.size(), 0)) > 0) {
                wr_buffer = wr_buffer.substr(r);
            }
            return r;
        }

        virtual void onClose(const SOCKET socket, shared_ptr<PassiveSocket> &current) {
            for (const auto &func: closing) {
                func(socket, current);
            }
        }

        bool empty() const {
            return wr_buffer.empty();
        }
    };

    class PassiveServer : public PassiveSocket {
    protected:
        bool singleUse = false;
        function<void(shared_ptr<TcpClient>, shared_ptr<PassiveSocket>)> func;

    public:
        explicit PassiveServer(function<void(shared_ptr<TcpClient>, shared_ptr<PassiveSocket>)> proc,
                               const bool singleUse) : singleUse(singleUse), func(std::move(proc)) {}

        int recvData(const SOCKET socket, shared_ptr<PassiveSocket> &current) override {
            TcpServer server(socket);
            try {
                func(shared_ptr<TcpClient>(server.accept()), current);
            } catch (runtime_error &ex) {
                cerr << ex.what() << endl;
            }
            if (singleUse) {
                server.close();
            }
            return 1;
        }
    };

    inline shared_ptr<PassiveSocket> mp[FD_MAX];

    class Epoll {
    protected:
        HANDLE epoll_fd;
        atomic_int conn{};
        thread th;
        epoll_event events[1024]{};

        void modifySocket(SOCKET socket_fd, const uint32_t m) {
            epoll_event event{};
            event.events = m;
            event.data.fd = socket_fd;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, socket_fd, &event) == -1) {
                cerr << "epoll_ctl modification failed code: " << getErrorCode() << endl;
                --conn;
            }
        }

    public:
        explicit Epoll() {
            epoll_fd = epoll_create1(0);
            conn = 0;
        }

        ~Epoll() {
            epoll_close(epoll_fd);
            if (th.joinable())
                th.join();
        }


        void syncEpollThread() {
            if (th.joinable())
                th.join();
            th = thread([&]() {
                cout << "Creating new Epoll" << endl << flush;
                while (conn) {
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
                                if (current->recvData(events[i].data.fd, current) == 0) {
                                    unregisterSocket(client);
                                }
                                if (!current->empty()) {
                                    modifySocket(events[i].data.fd, EPOLLOUT);
                                }
                            }
                            if (events[i].events & EPOLLOUT) {
                                if (current->sendData(events[i].data.fd) == 0) {
                                    modifySocket(events[i].data.fd, EPOLLIN);
                                }
                            }
                            if (events[i].events & EPOLLHUP) {
                                while (!current->recvData(events[i].data.fd, current)) {}
                                unregisterSocket(client);
                            }
                        }
                    }
                }
                cout << "Epoll thread exit" << endl;
            });
        }

        void registerSocket(const SOCKET socket, const shared_ptr<PassiveSocket> &passive) {
            cout << this << "Socket Connected " << conn << endl;
            mp[socket] = passive;
            passive->epoll_fd = epoll_fd;
            passive->socket_fd = socket;
            epoll_event event{};
            event.events = EPOLLIN;
            event.data.fd = socket;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket, &event) == -1) {
                cerr << "epoll_ctl adding failed code:" << getErrorCode() << endl;
                return;
            }
            if (!conn++) {
                syncEpollThread();
            }
        }

        void unregisterSocket(TcpClient &socket) {
            cout << "Connection closed" << endl;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket.getFD(), nullptr) == -1) {
                cerr << "epoll_ctl deleting failed" << endl;
                close();
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
        }
    };
}

#endif
