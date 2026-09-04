#ifndef OCELOT_PROTOCOL_HPP
#define OCELOT_PROTOCOL_HPP

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>

#include "logging.hpp"
#include "unisocket.hpp"

namespace protocol {
    using namespace std;
    using namespace unisocket;

    typedef unsigned char byte;

    inline byte method5[] = {0x05, 0x00};
    inline byte success4[] = {0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    inline string httpSucceed = "HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n";

    struct NetworkAddr {
        string ip;
        int port = -1;

        bool valid() const { return port > 0 && port < 65536 && !ip.empty(); }
    };

    struct UdpPacket {
        NetworkAddr destination;
        size_t payload_offset = 0;

        bool valid() const { return destination.valid() && payload_offset > 0; }
    };

    inline string socks5Reply(const byte status, const uint32_t ipv4 = 0, const uint16_t port = 0) {
        string reply(10, '\0');
        reply[0] = 0x05;
        reply[1] = static_cast<char>(status);
        reply[3] = 0x01;
        memcpy(reply.data() + 4, &ipv4, sizeof(ipv4));
        reply[8] = static_cast<char>(port >> 8);
        reply[9] = static_cast<char>(port & 0xff);
        return reply;
    }

    /// Parses the address portion of a SOCKS5 CONNECT request.
    ///
    /// Every field is now length-checked.  The previous version indexed
    /// straight into the buffer, so a truncated or hostile request read past
    /// the end of the string.
    inline NetworkAddr parseSocks5(const string &buffer) {
        NetworkAddr res;
        // The control opcode already identifies this as a TCP relay request.
        // Do not require VER/CMD here: clients predating the UDP extension
        // forwarded HTTP and SOCKS4 destinations with these reserved bytes at
        // zero, and servers must remain compatible during rolling upgrades.
        if (buffer.size() < 5)
            return res;

        size_t pos = 4;
        switch (static_cast<byte>(buffer[3])) {
            case 0x01: {
                if (buffer.size() < pos + 4 + 2)
                    return res;
                char ip[16];
                snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                         static_cast<byte>(buffer[pos]), static_cast<byte>(buffer[pos + 1]),
                         static_cast<byte>(buffer[pos + 2]), static_cast<byte>(buffer[pos + 3]));
                res.ip = ip;
                pos += 4;
                break;
            }
            case 0x03: {
                const size_t len = static_cast<byte>(buffer[pos]);
                ++pos;
                if (buffer.size() < pos + len + 2)
                    return res;
                res.ip = buffer.substr(pos, len);
                pos += len;
                break;
            }
            case 0x04:
                LOG_WARN("IPv6 destinations are not supported yet");
                return res;
            default:
                LOG_WARN("Invalid network address format (type %u)", static_cast<byte>(buffer[3]));
                return res;
        }

        res.port = static_cast<int>(static_cast<byte>(buffer[pos])) << 8 | static_cast<byte>(buffer[pos + 1]);
        return res;
    }

    /// Parses an RFC 1928 SOCKS5 UDP request.  Fragmentation is deliberately
    /// rejected: virtually all SOCKS implementations require FRAG=0 and the
    /// RFC permits a relay to drop fragments it does not implement.
    inline UdpPacket parseSocks5Udp(const string &buffer) {
        UdpPacket packet;
        if (buffer.size() < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0)
            return packet;

        size_t pos = 4;
        switch (static_cast<byte>(buffer[3])) {
            case 0x01: {
                if (buffer.size() < pos + 4 + 2)
                    return packet;
                char ip[16];
                snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                         static_cast<byte>(buffer[pos]), static_cast<byte>(buffer[pos + 1]),
                         static_cast<byte>(buffer[pos + 2]), static_cast<byte>(buffer[pos + 3]));
                packet.destination.ip = ip;
                pos += 4;
                break;
            }
            case 0x03: {
                if (buffer.size() < pos + 1)
                    return packet;
                const size_t len = static_cast<byte>(buffer[pos++]);
                if (len == 0 || buffer.size() < pos + len + 2)
                    return packet;
                packet.destination.ip = buffer.substr(pos, len);
                pos += len;
                break;
            }
            case 0x04:
                // The transport is currently IPv4-only on both platforms.
                return packet;
            default:
                return packet;
        }
        packet.destination.port = static_cast<int>(static_cast<byte>(buffer[pos])) << 8
                                  | static_cast<byte>(buffer[pos + 1]);
        packet.payload_offset = pos + 2;
        if (!packet.destination.valid())
            packet.payload_offset = 0;
        return packet;
    }

    inline string wrapSocks5Udp(const sockaddr_in &source, const char *payload, const size_t length) {
        string packet(10 + length, '\0');
        packet[3] = 0x01;
        memcpy(packet.data() + 4, &source.sin_addr.s_addr, sizeof(source.sin_addr.s_addr));
        const uint16_t port = ntohs(source.sin_port);
        packet[8] = static_cast<char>(port >> 8);
        packet[9] = static_cast<char>(port & 0xff);
        if (length)
            memcpy(packet.data() + 10, payload, length);
        return packet;
    }

    /// Reads the address portion of a SOCKS5 request straight off the wire and
    /// returns it verbatim, ready to be forwarded to the relay.
    inline string interceptSocks5(const shared_ptr<TcpClient> &stream) {
        stringstream ss;
        string buffer;
        if (!stream->read(buffer, 4))
            return "";
        ss << buffer;
        switch (static_cast<byte>(buffer[3])) {
            case 0x01:
                if (!stream->read(buffer, 4))
                    return "";
                ss << buffer;
                break;
            case 0x03: {
                byte len = 0;
                if (!stream->read<byte>(len))
                    return "";
                ss << len;
                if (!stream->read(buffer, len))
                    return "";
                ss << buffer;
                break;
            }
            case 0x04:
                if (!stream->read(buffer, 16))
                    return "";
                ss << buffer;
                break;
            default:
                LOG_WARN("Invalid network address format (type %u)", static_cast<byte>(buffer[3]));
                return "";
        }
        if (!stream->read(buffer, 2))
            return "";
        ss << buffer;
        return ss.str();
    }

    /// Detects which proxy dialect the local application is speaking and
    /// completes the greeting.  Returns 5, 4, 1 (HTTP CONNECT) or 0.
    inline int certificate(const shared_ptr<TcpClient> &stream) {
        string buffer;
        if (!stream->read(buffer, 2))
            return 0;

        if (static_cast<byte>(buffer[0]) == 0x05) {
            const size_t methods = static_cast<byte>(buffer[1]);
            if (methods && !stream->read(buffer, static_cast<int>(methods)))
                return 0;
            stream->write(reinterpret_cast<char *>(method5), sizeof(method5));
            return 5;
        }
        if (static_cast<byte>(buffer[0]) == 0x04) {
            stream->write(reinterpret_cast<char *>(success4), 8);
            return 4;
        }
        if (buffer[0] == 'C' && buffer[1] == 'O') {
            if (!stream->read(buffer, 6))
                return 0;
            if (buffer.compare(0, 5, "NNECT") == 0)
                return 1;
        }
        return 0;
    }

    inline string socks4To5(const string &socks4) {
        if (socks4.size() < 6)
            return "";
        string buffer(10, '\0');
        buffer[0] = 0x05;
        buffer[1] = 0x01;
        buffer[3] = 0x01;
        for (int i = 4; i < 8; i++)
            buffer[i] = socks4[i - 2];
        buffer[8] = socks4[0];
        buffer[9] = socks4[1];
        return buffer;
    }

    inline string HttpToSocks5(const string &http) {
        const string url = http.substr(0, http.find_first_of(" \r\n"));
        if (url.empty())
            return "";
        const size_t colon = url.find_last_of(':');
        const string hostname = colon == string::npos ? url : url.substr(0, colon);
        const int port = colon == string::npos ? 80 : atoi(url.c_str() + colon + 1);
        if (hostname.empty() || hostname.size() > 255 || port <= 0 || port > 65535)
            return "";

        string data(5 + hostname.size() + 2, '\0');
        data[0] = 0x05;
        data[1] = 0x01;
        data[3] = 0x03;
        data[4] = static_cast<char>(hostname.size());
        memcpy(&data[5], hostname.data(), hostname.size());
        data[5 + hostname.size()] = static_cast<char>(port >> 8);
        data[6 + hostname.size()] = static_cast<char>(port & 0xFF);
        return data;
    }
}

#endif
