#include <chrono>
#include <cstdio>
#include <functional>
#include <memory>
#include <thread>

#include "ocelot/libocelot.hpp"

using namespace std;
using namespace std::chrono;
using namespace crypto;
using namespace io;
using namespace ocelot;
using namespace unisocket;

namespace {
    bool waitUntil(const function<bool()> &predicate, const milliseconds timeout) {
        const auto end = steady_clock::now() + timeout;
        while (steady_clock::now() < end) {
            if (predicate())
                return true;
            this_thread::sleep_for(milliseconds(25));
        }
        return predicate();
    }

    int fail(const char *message) {
        fprintf(stderr, "FAIL: %s\n", message);
        return 1;
    }
}

int main() {
    init();

    // TCP CONNECT and UDP ASSOCIATE use related but distinct SOCKS5 packet
    // layouts.  Keep their command, fragmentation and payload boundaries
    // covered independently.
    {
        const string connect_request("\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x35", 10);
        const NetworkAddr address = parseSocks5(connect_request);
        if (!address.valid() || address.ip != "127.0.0.1" || address.port != 53)
            return fail("SOCKS5 TCP destination parsing failed");

        const string payload = "udp-payload";
        const string udp_request = string("\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35", 10) + payload;
        const UdpPacket udp = parseSocks5Udp(udp_request);
        if (!udp.valid() || udp.destination.ip != "127.0.0.1" || udp.destination.port != 53
            || udp_request.substr(udp.payload_offset) != payload)
            return fail("SOCKS5 UDP destination parsing failed");

        string fragmented = udp_request;
        fragmented[2] = 1;
        if (parseSocks5Udp(fragmented).valid())
            return fail("fragmented SOCKS5 UDP packet was accepted");

        sockaddr_in source{};
        source.sin_family = AF_INET;
        source.sin_port = htons(5353);
        inet_pton(AF_INET, "127.0.0.2", &source.sin_addr);
        const string wrapped = wrapSocks5Udp(source, payload.data(), payload.size());
        const UdpPacket wrapped_packet = parseSocks5Udp(wrapped);
        if (!wrapped_packet.valid() || wrapped_packet.destination.ip != "127.0.0.2"
            || wrapped_packet.destination.port != 5353 || wrapped.substr(wrapped_packet.payload_offset) != payload)
            return fail("SOCKS5 UDP response wrapping failed");
    }

    // Relay callbacks are stored by the source socket.  They must observe the
    // destination weakly or the two directions form an uncollectable cycle.
    {
        weak_ptr<PassiveSocket> weak_a;
        weak_ptr<PassiveSocket> weak_b;
        {
            auto a = make_shared<PassiveSocket>();
            auto b = make_shared<PassiveSocket>();
            weak_a = a;
            weak_b = b;
            a->copyTo(b);
            b->copyTo(a);
            PassiveSocket::link(a, b);
        }
        if (!weak_a.expired() || !weak_b.expired())
            return fail("plain relay handlers retained a shared_ptr cycle");
    }

    // The encrypted channel has its own framing callback and needs the same
    // ownership guarantee as the plain relay implementation.
    {
        weak_ptr<PassiveSocket> weak_plain;
        weak_ptr<PassiveSocket> weak_channel;
        {
            auto aes = make_shared<AES_CBC>(string(32, 'k'), string(16, 'i'));
            auto plain = make_shared<PassiveSocket>();
            auto channel = make_shared<PassiveOcelotChannel>(aes);
            weak_plain = plain;
            weak_channel = channel;
            plain->copyTo(channel);
            channel->copyTo(plain);
            PassiveSocket::link(plain, channel);
        }
        if (!weak_plain.expired() || !weak_channel.expired())
            return fail("encrypted relay handlers retained a shared_ptr cycle");
    }

    // A UDP tunnel has no useful half-closed state.  Closing its TCP carrier
    // must immediately retire both the encrypted channel and its UDP socket,
    // rather than leaving two handles until the generic five-minute timeout.
    {
        TcpServer listener("127.0.0.1", 0);
        TcpClient sender("127.0.0.1", listener.getPort());
        unique_ptr<TcpClient> accepted(listener.accept());
        if (!accepted)
            return fail("UDP tunnel test connection was not accepted");

        UdpSocket outbound("127.0.0.1", 0);
        auto aes = make_shared<AES_CBC>(string(32, 'k'), string(16, 'i'));
        auto udp = make_shared<PassiveRemoteUdp>();
        auto channel = make_shared<PassiveUdpChannel>(aes);
        channel->copyTo(udp);
        PassiveSocket::link(udp, channel);

        Epoll epoll;
        epoll.registerSocket(outbound.release(), udp);
        epoll.registerSocket(accepted->release(), channel);
        sender.close();
        if (!waitUntil([&] { return epoll.connections() == 0; }, seconds(3)))
            return fail("UDP tunnel EOF did not retire both descriptors");
        listener.close();
    }

    // Epoll owns registered sockets through the global descriptor table.  Its
    // destructor must remove those entries even when no close event arrived.
    {
        weak_ptr<PassiveSocket> weak_registered;
        {
            const TcpServer listener("127.0.0.1", 0);
            auto passive = make_shared<PassiveServer>(
                [](const shared_ptr<TcpClient> &, const shared_ptr<PassiveSocket> &) {}, true);
            weak_registered = passive;
            Epoll epoll;
            epoll.registerSocket(listener.getFD(), passive);
        }
        if (!weak_registered.expired())
            return fail("Epoll destruction retained a registered socket");
    }

    // An abandoned one-shot listener must disappear without ever receiving an
    // accept event.  This is the failure mode that used to leak random ports.
    {
        Epoll epoll;
        for (int i = 0; i < 64; ++i) {
            const TcpServer listener("127.0.0.1", 0);
            auto passive = make_shared<PassiveServer>(
                [](const shared_ptr<TcpClient> &, const shared_ptr<PassiveSocket> &) {}, true);
            passive->expireAfter(milliseconds(100));
            epoll.registerSocket(listener.getFD(), passive);
        }
        if (!waitUntil([&] { return epoll.connections() == 0; }, seconds(3)))
            return fail("fixed-lifetime listeners were not reclaimed");
    }

    // Ordinary idle sockets have no application deadline.  This is important
    // for WebSockets, tunnels and other legitimately quiet long connections.
    {
        TcpServer listener("127.0.0.1", 0);
        TcpClient sender("127.0.0.1", listener.getPort());
        unique_ptr<TcpClient> accepted(listener.accept());
        if (!accepted)
            return fail("idle test connection was not accepted");

        auto sink = make_shared<PassiveSocket>();
        auto passive = make_shared<PassiveSocket>();
        passive->copyTo(sink);
        const SOCKET fd = accepted->release();
        Epoll epoll;
        epoll.registerSocket(fd, passive);
        this_thread::sleep_for(milliseconds(1300));
        if (epoll.connections() != 1)
            return fail("ordinary idle socket was closed by the expiry scanner");
        epoll.destroySocket(fd);
        listener.close();
    }

    // Activity-based expiry is refreshed by traffic.  It is used after FIN so
    // a slow one-way response remains valid as long as bytes keep progressing.
    {
        TcpServer listener("127.0.0.1", 0);
        TcpClient sender("127.0.0.1", listener.getPort());
        unique_ptr<TcpClient> accepted(listener.accept());
        if (!accepted)
            return fail("test connection was not accepted");

        int keepalive = 0;
        socklen_t option_size = sizeof(keepalive);
        if (getsockopt(sender.getFD(), SOL_SOCKET, SO_KEEPALIVE,
                       reinterpret_cast<char *>(&keepalive), &option_size) == SOCKET_ERROR || keepalive != 1)
            return fail("TCP keepalive was not enabled");

        auto sink = make_shared<PassiveSocket>();
        auto passive = make_shared<PassiveSocket>();
        passive->copyTo(sink);
        passive->expireWhenIdleFor(milliseconds(1200));

        Epoll epoll;
        epoll.registerSocket(accepted->release(), passive);
        for (int i = 0; i < 3; ++i) {
            this_thread::sleep_for(milliseconds(700));
            if (!sender.write(static_cast<char>('a' + i)))
                return fail("test activity could not be sent");
            this_thread::sleep_for(milliseconds(100));
            if (epoll.connections() != 1)
                return fail("active socket expired while data was progressing");
        }
        if (!waitUntil([&] { return epoll.connections() == 0; }, seconds(4)))
            return fail("inactive activity-based socket was not reclaimed");
        listener.close();
    }

    // An abortive close (RST), representative of a crashed client process,
    // must tear down both registered halves of a tunnel immediately.
    {
        TcpServer listener("127.0.0.1", 0);
        TcpClient sender_a("127.0.0.1", listener.getPort());
        unique_ptr<TcpClient> accepted_a(listener.accept());
        TcpClient sender_b("127.0.0.1", listener.getPort());
        unique_ptr<TcpClient> accepted_b(listener.accept());
        if (!accepted_a || !accepted_b)
            return fail("RST test connections were not accepted");

        auto side_a = make_shared<PassiveSocket>();
        auto side_b = make_shared<PassiveSocket>();
        side_a->copyTo(side_b);
        side_b->copyTo(side_a);
        PassiveSocket::link(side_a, side_b);

        Epoll epoll;
        epoll.registerSocket(accepted_a->release(), side_a);
        epoll.registerSocket(accepted_b->release(), side_b);

        linger abortive{};
        abortive.l_onoff = 1;
        abortive.l_linger = 0;
        if (setsockopt(sender_a.getFD(), SOL_SOCKET, SO_LINGER,
                       reinterpret_cast<const char *>(&abortive), sizeof(abortive)) == SOCKET_ERROR)
            return fail("could not configure abortive close");
        sender_a.close();

        if (!waitUntil([&] { return epoll.connections() == 0; }, seconds(3)))
            return fail("RST did not retire both tunnel halves");
        listener.close();
    }

    puts("socket lifecycle tests passed");
    return 0;
}
