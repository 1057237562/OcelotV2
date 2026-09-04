#ifndef OCELOT_IO_HPP
#define OCELOT_IO_HPP

#include "logging.hpp"
#include "unisocket.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#include "wepoll.h"
#else
#include <sys/epoll.h>

#define HANDLE int
#define epoll_close(x) ::close(x)
#endif

namespace io {
    using namespace std;
    using namespace unisocket;

    constexpr size_t FD_MAX = 65536;

    /// Size of a single read from a relayed socket.  Larger reads mean fewer
    /// syscalls, fewer tunnel frames and less per-frame crypto overhead.
    constexpr size_t IO_BUFFER = 16384;

    /// Flow control.  Without it a fast producer can queue unbounded memory
    /// against a slow consumer; with it the peer's reads are paused until the
    /// backlog drains, and TCP pushes back on the original sender.
    constexpr size_t WRITE_HIGH_WATER = 256 * 1024;
    constexpr size_t WRITE_LOW_WATER = 64 * 1024;

    /// Compact the write buffer once this many bytes at its head have been
    /// sent, instead of memmoving after every partial send.
    constexpr size_t WRITE_COMPACT_THRESHOLD = 64 * 1024;

    /// A full-duplex long connection has no application idle timeout.  This
    /// timeout begins only after one direction has received FIN.  Any further
    /// bytes in the remaining direction refresh it, so large/slow responses
    /// continue normally while abandoned half-closed tunnels are reclaimed.
    constexpr auto HALF_CLOSE_IDLE_TIMEOUT = chrono::minutes(5);

    inline long long monotonicMilliseconds() {
        return chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();
    }

    template<typename T>
    string convertBit(T &&val) {
        return string(reinterpret_cast<const char *>(&val), sizeof(T));
    }

    class Epoll;

    /// A socket driven by an Epoll loop.
    ///
    /// Reads are expressed as a queue of expectations: a positive length means
    /// "call me with exactly this many bytes", a negative length means "call me
    /// with whatever has arrived, rounded down to a multiple of |len|".
    class PassiveSocket {
        friend class Epoll;

    protected:
        using Handler = function<void(char *, int, SOCKET, const shared_ptr<PassiveSocket> &)>;

        string rd_buffer;
        string wr_buffer;
        size_t ptr = 0; ///< bytes currently held in rd_buffer
        size_t wr_ptr = 0; ///< bytes of wr_buffer already handed to the kernel
        queue<pair<long long, Handler> > que;
        vector<function<void(SOCKET, const shared_ptr<PassiveSocket> &)> > closing;

        weak_ptr<PassiveSocket> peer;
        uint32_t interest = 0;
        bool read_closed = false; ///< we will not read from this socket again
        bool write_closed = false; ///< FIN already sent
        bool want_shutdown_write = false; ///< send FIN as soon as the buffer drains
        bool read_paused = false; ///< peer's write backlog is too large
        bool dead = false;

        /// Zero means no lifetime policy.  A positive expiry_period_ms makes
        /// the deadline activity-based; fixed deadlines leave the period at 0.
        atomic_llong expiry_at_ms{0};
        atomic_llong expiry_period_ms{0};

    public:
        HANDLE epoll_fd = 0;
        SOCKET socket_fd = INVALID_SOCKET;

        PassiveSocket() = default;

        PassiveSocket(const PassiveSocket &) = delete;

        PassiveSocket &operator=(const PassiveSocket &) = delete;

        virtual ~PassiveSocket() { LOG_DEBUG("PassiveSocket %p destroyed", static_cast<void *>(this)); }

        void close(const function<void(SOCKET, const shared_ptr<PassiveSocket> &)> &func) { closing.emplace_back(func); }

        /// Ties two sockets together so that tearing one down flushes and then
        /// closes the other.  Without this, half of every finished tunnel was
        /// left registered in epoll forever.
        static void link(const shared_ptr<PassiveSocket> &a, const shared_ptr<PassiveSocket> &b) {
            a->peer = b;
            b->peer = a;
        }

        template<typename T>
        void read(function<void(T, SOCKET, const shared_ptr<PassiveSocket> &)> func) {
            que.emplace(static_cast<long long>(sizeof(T)),
                        [func](char *buf, int, const SOCKET socket, const shared_ptr<PassiveSocket> &current) {
                            T val;
                            memcpy(&val, buf, sizeof(T));
                            func(val, socket, current);
                        });
        }

        template<typename T>
        void read(T *val) {
            que.emplace(static_cast<long long>(sizeof(T)),
                        [val](char *buf, int, SOCKET, const shared_ptr<PassiveSocket> &) {
                            memcpy(val, buf, sizeof(T));
                        });
        }

        void read(const int len, const function<void(char *, SOCKET, const shared_ptr<PassiveSocket> &)> &func) {
            if (len <= 0) {
                LOG_WARN("PassiveSocket::read ignored a non-positive length (%d)", len);
                return;
            }
            que.emplace(len, [func](char *buf, int, const SOCKET socket, const shared_ptr<PassiveSocket> &current) {
                func(buf, socket, current);
            });
        }

        /// Queues `len` bytes and pushes them out immediately.
        ///
        /// The old implementation only appended to the buffer and flipped the
        /// socket's epoll interest to EPOLLOUT, so every single write waited for
        /// a full epoll_wait round trip before a byte left the machine -- and
        /// while it waited, EPOLLIN was dropped, so the socket also went deaf.
        /// Sending inline costs one syscall and removes that latency entirely;
        /// EPOLLOUT is now only armed when the kernel buffer is actually full.
        virtual void write(const char *buf, const int len) {
            if (dead || write_closed || want_shutdown_write || len <= 0)
                return;
            wr_buffer.append(buf, len);
            if (socket_fd == INVALID_SOCKET)
                return; // not registered yet; the loop will flush on arrival
            if (sendData(socket_fd) < 0) {
                // The connection is gone.  Mark both halves finished so the
                // event loop retires this socket (and its peer) promptly
                // instead of leaving it parked with no interest bits.
                read_closed = true;
                write_closed = true;
                want_shutdown_write = false;
                wr_buffer.clear();
                wr_ptr = 0;
            }
            updateInterest();
        }

        template<typename T>
        void write(T *val) { write(reinterpret_cast<const char *>(val), sizeof(T)); }

        template<typename T>
        void write(T &&val) { write(&val); }

        /// Relays everything arriving on this socket to `target`.
        virtual void copyTo(const shared_ptr<PassiveSocket> &target) {
            while (!que.empty())
                que.pop();
            ptr = 0;
            // The handler lives inside this socket.  Capturing target strongly
            // here would make two linked relay handlers own each other forever
            // after both descriptors had been removed from epoll.
            const weak_ptr<PassiveSocket> weak_target = target;
            que.emplace(-1, [weak_target](const char *buf, const int len, SOCKET,
                                          const shared_ptr<PassiveSocket> &) {
                if (const auto target = weak_target.lock())
                    target->write(buf, len);
            });
        }

        size_t pendingBytes() const { return wr_buffer.size() - wr_ptr; }

        bool pendingOutput() const { return wr_ptr < wr_buffer.size(); }

        bool empty() const { return !pendingOutput(); }

        bool isDead() const { return dead; }

        /// Fixed lifetime, used by a one-shot listener while it waits for the
        /// client to connect.  Socket activity does not extend this deadline.
        void expireAfter(const chrono::milliseconds timeout) {
            expiry_period_ms.store(0);
            expiry_at_ms.store(monotonicMilliseconds() + timeout.count());
        }

        /// Inactivity lifetime, used only once a tunnel has become half-closed.
        void expireWhenIdleFor(const chrono::milliseconds timeout) {
            expiry_period_ms.store(timeout.count());
            expiry_at_ms.store(monotonicMilliseconds() + timeout.count());
        }

        void clearExpiry() {
            expiry_at_ms.store(0);
            expiry_period_ms.store(0);
        }

        /// Stops accepting input, flushes any reply already queued, sends FIN
        /// and lets settle() retire the descriptor.  Protocol handlers use
        /// this when a stream can no longer be parsed safely.
        void closeAfterWrite() {
            read_closed = true;
            want_shutdown_write = true;
            updateInterest();
        }

        /// @return 1 keep going, 0 peer closed cleanly, -1 fatal error.
        virtual int recvData(const SOCKET socket, const shared_ptr<PassiveSocket> &current) {
            for (;;) {
                if (que.empty()) {
                    // Nothing is expected any more.  Returning "keep going"
                    // here would spin at 100% CPU, because level-triggered
                    // epoll re-reports the unread bytes forever.
                    LOG_DEBUG("socket %d has no pending read expectation, closing", socket);
                    return 0;
                }
                fitReadBuffer();
                if (ptr >= rd_buffer.size())
                    return 1;

                const size_t room = rd_buffer.size() - ptr;
                const int r = recv(socket, rd_buffer.data() + ptr, room, 0);
                if (r == 0)
                    return 0;
                if (r < 0)
                    return wouldBlock() ? 1 : -1;

                noteActivity();
                ptr += static_cast<size_t>(r);
                consume(socket, current);
                if (dead || read_closed)
                    return 1;
                if (static_cast<size_t>(r) < room)
                    return 1; // socket drained; save a syscall
                // Stop draining once the peer is already backed up, so a fast
                // source cannot queue unbounded memory inside a single event.
                if (const auto p = peer.lock(); p && p->pendingBytes() > WRITE_HIGH_WATER)
                    return 1;
            }
        }

        /// @return 0 on success (possibly with data still buffered), -1 fatal.
        virtual int sendData(const SOCKET socket) {
            while (wr_ptr < wr_buffer.size()) {
                const int r = send(socket, wr_buffer.data() + wr_ptr, wr_buffer.size() - wr_ptr, SEND_FLAGS);
                if (r > 0) {
                    noteActivity();
                    wr_ptr += static_cast<size_t>(r);
                    continue;
                }
                if (r < 0 && wouldBlock())
                    break;
                return -1;
            }
            if (wr_ptr == wr_buffer.size()) {
                wr_buffer.clear();
                wr_ptr = 0;
            } else if (wr_ptr >= WRITE_COMPACT_THRESHOLD) {
                // Amortised compaction; the original substr()'d the whole
                // backlog on every partial send, which is quadratic.
                wr_buffer.erase(0, wr_ptr);
                wr_ptr = 0;
            }
            return 0;
        }

        virtual void onClose(const SOCKET socket, const shared_ptr<PassiveSocket> &current) {
            for (const auto &func: closing)
                func(socket, current);
        }

        /// Re-arms the socket's epoll interest to match its current state.
        void updateInterest() {
            if (dead || socket_fd == INVALID_SOCKET)
                return;
            uint32_t want = 0;
            if (!read_closed && !read_paused)
                want |= EPOLLIN | EPOLLRDHUP;
            if (pendingOutput())
                want |= EPOLLOUT;
            if (want == interest)
                return;
            epoll_event event{};
            event.events = want;
            event.data.fd = socket_fd;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, socket_fd, &event) == -1) {
                LOG_WARN("epoll_ctl(MOD) failed on fd %d: %d", socket_fd, getErrorCode());
                return;
            }
            interest = want;
        }

    protected:
        bool expiryReached(const long long now_ms) const {
            const long long deadline = expiry_at_ms.load();
            return deadline > 0 && now_ms >= deadline;
        }

        void noteActivity() {
            const long long now = monotonicMilliseconds();
            const long long period = expiry_period_ms.load();
            if (period > 0)
                expiry_at_ms.store(now + period);
            if (const auto p = peer.lock()) {
                const long long peer_period = p->expiry_period_ms.load();
                if (peer_period > 0)
                    p->expiry_at_ms.store(now + peer_period);
            }
        }

        size_t desiredReadSize() const {
            const long long want = que.front().first;
            return want > 0 ? static_cast<size_t>(want) : IO_BUFFER;
        }

        void fitReadBuffer() {
            const size_t want = desiredReadSize();
            if (rd_buffer.size() != want && want >= ptr)
                rd_buffer.resize(want);
        }

        void consume(const SOCKET socket, const shared_ptr<PassiveSocket> &current) {
            while (!que.empty() && !dead) {
                const long long want = que.front().first;
                if (want > 0) {
                    const size_t need = static_cast<size_t>(want);
                    if (ptr < need)
                        return;
                    // Pop before dispatching: handlers routinely queue the next
                    // expectation from inside the callback.
                    Handler handler = std::move(que.front().second);
                    que.pop();
                    ptr = 0;
                    handler(rd_buffer.data(), static_cast<int>(need), socket, current);
                } else {
                    const size_t chunk = static_cast<size_t>(-want);
                    if (ptr < chunk)
                        return;
                    const size_t len = ptr - ptr % chunk;
                    que.front().second(rd_buffer.data(), static_cast<int>(len), socket, current);
                    const size_t rest = ptr - len;
                    if (rest)
                        memmove(rd_buffer.data(), rd_buffer.data() + len, rest);
                    ptr = rest;
                    return; // streaming handlers stay queued
                }
            }
        }
    };

    /// Accepts connections from inside the event loop.
    class PassiveServer : public PassiveSocket {
    protected:
        bool singleUse = false;
        function<void(const shared_ptr<TcpClient> &, const shared_ptr<PassiveSocket> &)> func;

    public:
        PassiveServer(function<void(const shared_ptr<TcpClient> &, const shared_ptr<PassiveSocket> &)> proc,
                      const bool singleUse) : singleUse(singleUse), func(std::move(proc)) {}

        int recvData(const SOCKET socket, const shared_ptr<PassiveSocket> &current) override {
            const TcpServer server(socket);
            for (;;) {
                const auto client = shared_ptr<TcpClient>(server.accept());
                if (!client)
                    return wouldBlock() ? 1 : -1;
                try {
                    func(client, current);
                } catch (const runtime_error &ex) {
                    LOG_WARN("accept handler failed: %s", ex.what());
                }
                if (singleUse) {
                    // Report EOF so the loop unregisters and closes the
                    // listener properly.  Closing it here (as before) left the
                    // fd table entry dangling and never decremented the count.
                    return 0;
                }
            }
        }
    };

    // The fd -> socket table is shared by every Epoll instance.  Registration
    // happens from whichever thread accepted the connection, so the slots are
    // guarded by a small bank of striped mutexes rather than one global lock.
    inline shared_ptr<PassiveSocket> mp[FD_MAX];

    inline mutex &slotMutex(const SOCKET fd) {
        static mutex locks[64];
        return locks[static_cast<size_t>(fd) & 63];
    }

    inline shared_ptr<PassiveSocket> getSocket(const SOCKET fd) {
        if (fd < 0 || static_cast<size_t>(fd) >= FD_MAX)
            return nullptr;
        lock_guard<mutex> lk(slotMutex(fd));
        return mp[fd];
    }

    inline void setSocket(const SOCKET fd, const shared_ptr<PassiveSocket> &s) {
        if (fd < 0 || static_cast<size_t>(fd) >= FD_MAX)
            return;
        lock_guard<mutex> lk(slotMutex(fd));
        mp[fd] = s;
    }

    class Epoll {
    protected:
        HANDLE epoll_fd;
        atomic_int conn{0};
        atomic_bool running{true};
        thread th;
        epoll_event events[1024]{};
        mutex registered_mutex;
        unordered_map<SOCKET, weak_ptr<PassiveSocket> > registered;
        chrono::steady_clock::time_point next_expiry_scan = chrono::steady_clock::now();

    public:
        Epoll() {
            init();
            epoll_fd = epoll_create1(0);
#ifdef _WIN32
            if (epoll_fd == nullptr)
#else
            if (epoll_fd == -1)
#endif
                throw runtime_error("epoll_create1 failed");
            // One long-lived thread per Epoll.  The old code started a thread on
            // the first registration and stopped it when the last socket went
            // away -- except the thread sat in epoll_wait(-1) and never noticed,
            // so the next registration deadlocked joining it.
            th = thread([this] { loop(); });
        }

        Epoll(const Epoll &) = delete;

        Epoll &operator=(const Epoll &) = delete;

        ~Epoll() {
            running = false;
            if (th.joinable())
                th.join();

            // mp[] is the primary owner of registered PassiveSocket objects.
            // Closing only the epoll handle leaves those entries, their file
            // descriptors and all queued buffers alive when an Epoll instance
            // is stopped before process exit.
            vector<pair<SOCKET, shared_ptr<PassiveSocket> > > remaining;
            {
                lock_guard<mutex> lk(registered_mutex);
                remaining.reserve(registered.size());
                for (const auto &[fd, weak]: registered) {
                    if (const auto socket = weak.lock())
                        remaining.emplace_back(fd, socket);
                }
            }
            for (const auto &[fd, expected]: remaining) {
                if (getSocket(fd) == expected)
                    destroySocket(fd);
            }
            epoll_close(epoll_fd);
        }

        int connections() const { return conn.load(); }

        void registerSocket(const SOCKET socket, const shared_ptr<PassiveSocket> &passive) {
            if (socket < 0) {
                LOG_ERROR("refusing to register out-of-range fd %d", socket);
                return;
            }
            if (static_cast<size_t>(socket) >= FD_MAX) {
                // Ownership has already been transferred by TcpClient::release
                // at every call site, so refusing registration must also close
                // the descriptor or fd exhaustion turns into a permanent leak.
                LOG_ERROR("refusing to register out-of-range fd %d", socket);
                closesocket(socket);
                return;
            }
            // Blocking sockets in an epoll loop are a latency trap: one large
            // send() or one slow peer stalls every other connection on the
            // thread for as long as SO_SNDTIMEO allows.
            setNonBlocking(socket);
            setNoDelay(socket);

            passive->epoll_fd = epoll_fd;
            passive->socket_fd = socket;
            passive->interest = EPOLLIN | EPOLLRDHUP;
            // Publish the slot before the fd can produce events.
            setSocket(socket, passive);
            {
                lock_guard<mutex> lk(registered_mutex);
                registered[socket] = passive;
            }

            epoll_event event{};
            event.events = passive->interest;
            event.data.fd = socket;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket, &event) == -1) {
                LOG_ERROR("epoll_ctl(ADD) failed on fd %d: %d", socket, getErrorCode());
                setSocket(socket, nullptr);
                {
                    lock_guard<mutex> lk(registered_mutex);
                    registered.erase(socket);
                }
                passive->socket_fd = INVALID_SOCKET;
                closesocket(socket);
                return;
            }
            ++conn;
            LOG_DEBUG("epoll %p registered fd %d (%d live)", static_cast<void *>(this), socket, conn.load());

            // A non-blocking connect may already have completed, and data may
            // already be queued against the socket.
            passive->updateInterest();
        }

        /// Unregisters, closes and forgets `fd`, then winds down its peer.
        void destroySocket(const SOCKET fd) {
            const shared_ptr<PassiveSocket> current = getSocket(fd);
            if (!current || current->dead)
                return;

            current->dead = true;
            setSocket(fd, nullptr);
            {
                lock_guard<mutex> lk(registered_mutex);
                registered.erase(fd);
            }
            current->onClose(fd, current);

            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1)
                LOG_WARN("epoll_ctl(DEL) failed on fd %d: %d", fd, getErrorCode());
            closesocket(fd);
            --conn;
            LOG_DEBUG("epoll %p closed fd %d (%d live)", static_cast<void *>(this), fd, conn.load());

            if (const auto p = current->peer.lock(); p && !p->dead) {
                // Nothing can be delivered to us any more, so the peer has
                // nowhere to read to; let it flush what it already holds.
                p->read_closed = true;
                p->want_shutdown_write = true;
                if (p->pendingOutput()) {
                    // Abnormal termination can strand a large buffered tail
                    // against a peer that also vanished or stopped reading.
                    // Progress refreshes this deadline in sendData(); a stuck
                    // send is eventually reclaimed without limiting healthy
                    // full-duplex long connections.
                    p->expireWhenIdleFor(chrono::duration_cast<chrono::milliseconds>(HALF_CLOSE_IDLE_TIMEOUT));
                    p->updateInterest();
                } else
                    destroySocket(p->socket_fd);
            }
        }

    protected:
        /// One direction of the tunnel reached EOF.  The other direction may
        /// still have a response in flight, so only that half is shut down --
        /// closing both immediately truncates the tail of every response.
        void handleReadEof(const SOCKET fd, const shared_ptr<PassiveSocket> &s) {
            s->read_closed = true;
            s->expireWhenIdleFor(chrono::duration_cast<chrono::milliseconds>(HALF_CLOSE_IDLE_TIMEOUT));
            const auto p = s->peer.lock();
            if (p && !p->dead) {
                p->expireWhenIdleFor(chrono::duration_cast<chrono::milliseconds>(HALF_CLOSE_IDLE_TIMEOUT));
                p->want_shutdown_write = true;
                settle(p->socket_fd, p);
            }
            if (!p || p->dead) {
                s->want_shutdown_write = true;
            }
            settle(fd, s);
        }

        /// Applies any pending shutdown, retires fully-closed sockets and keeps
        /// the epoll interest and flow-control state in sync.
        void settle(const SOCKET fd, const shared_ptr<PassiveSocket> &s) {
            if (s->dead)
                return;
            if (s->want_shutdown_write && !s->write_closed && !s->pendingOutput()) {
#ifdef _WIN32
                ::shutdown(fd, SD_SEND);
#else
                ::shutdown(fd, SHUT_WR);
#endif
                s->write_closed = true;
            }
            if (s->read_closed && s->write_closed) {
                destroySocket(fd);
                return;
            }
            if (const auto p = s->peer.lock(); p && !p->dead) {
                const size_t backlog = s->pendingBytes();
                if (!p->read_paused && backlog > WRITE_HIGH_WATER) {
                    p->read_paused = true;
                    p->updateInterest();
                } else if (p->read_paused && backlog <= WRITE_LOW_WATER) {
                    p->read_paused = false;
                    p->updateInterest();
                }
            }
            s->updateInterest();
        }

        /// Retires fixed-deadline listeners and inactive half-closed tunnels.
        /// The registry is per Epoll instance, so one worker can never close a
        /// descriptor owned by another worker.  Scanning once per second keeps
        /// timeout handling cheap without requiring a timer thread per socket.
        void expireSockets() {
            const auto now = chrono::steady_clock::now();
            if (now < next_expiry_scan)
                return;
            next_expiry_scan = now + chrono::seconds(1);

            const long long now_ms = monotonicMilliseconds();
            vector<pair<SOCKET, shared_ptr<PassiveSocket> > > expired;
            {
                lock_guard<mutex> lk(registered_mutex);
                for (auto it = registered.begin(); it != registered.end();) {
                    const auto socket = it->second.lock();
                    if (!socket) {
                        it = registered.erase(it);
                        continue;
                    }
                    if (socket->expiryReached(now_ms))
                        expired.emplace_back(it->first, socket);
                    ++it;
                }
            }
            for (const auto &[fd, expected]: expired) {
                if (getSocket(fd) == expected) {
                    LOG_INFO("socket %d expired and will be closed", fd);
                    destroySocket(fd);
                }
            }
        }

        void loop() {
            LOG_INFO("epoll %p thread started", static_cast<void *>(this));
            while (running.load()) {
                const int r = epoll_wait(epoll_fd, events, 1024, 200);
                if (r < 0) {
                    if (wouldBlock())
                        continue;
                    LOG_ERROR("epoll_wait failed: %d", getErrorCode());
                    break;
                }
                for (int i = 0; i < r; i++) {
                    const SOCKET fd = events[i].data.fd;
                    const uint32_t ev = events[i].events;
                    const shared_ptr<PassiveSocket> current = getSocket(fd);
                    // A socket retired earlier in this same batch (typically the
                    // peer of one we just tore down) still shows up here.
                    if (!current || current->dead)
                        continue;

                    if (ev & (EPOLLERR | EPOLLHUP)) {
                        // Drain whatever is still readable, then retire it.
                        // The old code looped `while (!recvData(...))`, which
                        // never terminates: recv() on a hung-up socket returns
                        // 0 forever, so this spun a core at 100%.
                        current->recvData(fd, current);
                        destroySocket(fd);
                        continue;
                    }

                    if (ev & (EPOLLIN | EPOLLRDHUP)) {
                        const int rc = current->recvData(fd, current);
                        if (rc < 0) {
                            destroySocket(fd);
                            continue;
                        }
                        if (rc == 0) {
                            handleReadEof(fd, current);
                            if (current->dead)
                                continue;
                        }
                    }

                    if ((ev & EPOLLOUT) && !current->dead) {
                        if (current->sendData(fd) < 0) {
                            destroySocket(fd);
                            continue;
                        }
                    }

                    if (current->dead)
                        continue;
                    settle(fd, current);
                    if (const auto p = current->peer.lock(); p && !p->dead)
                        settle(p->socket_fd, p);
                }
                expireSockets();
            }
            LOG_INFO("epoll %p thread exiting", static_cast<void *>(this));
        }
    };
}

#endif
