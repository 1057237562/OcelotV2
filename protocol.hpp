#ifndef _PROTOCOL_HPP_
#define _PROTOCOL_HPP_
#include <sstream>
#include <unisocket>

namespace protocol {
    using namespace unisocket;
    inline byte success5[] = {0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    inline byte success4[] = {0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    inline std::string interceptSocks5(const std::shared_ptr<TcpClient> &stream) {
        std::stringstream ss;
        std::string buffer;
        buffer.resize(4);
        stream->read(buffer, 4);
        ss << buffer;
        switch (buffer[3]) {
            case 0x01:
                stream->read(buffer, 4);
                ss << buffer;
                break;
            case 0x03:
                unsigned char len;
                stream->read<unsigned char>(len);
                ss << len;
                buffer.resize(len);
                stream->read(buffer, len);
                ss << buffer;
                break;
            case 0x04:
                buffer.resize(16);
                stream->read(buffer, 16);
                ss << buffer;
                break;
            default: {
                std::cerr << "Invalid network address format" << endl;
                return "";
            }
        }
        buffer.resize(2);
        stream->read(buffer, 2);
        ss << buffer;
        return ss.str();
    }

    using namespace std;
    inline string httpSucceed = "HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n";

    inline int certificate(const shared_ptr<TcpClient> &stream) {
        string buffer;
        buffer.resize(2);
        stream->read(buffer, 2);
        if (buffer[0] == 0x05) {
            buffer.resize(static_cast<unsigned char>(buffer[1]));
            stream->read(buffer, buffer.size());
            stream->write(reinterpret_cast<char *>(success5), 12);
            return 5;
        }
        if (buffer[0] == 0x04) {
            stream->write(reinterpret_cast<char *>(success4), 8);
            return 4;
        }
        if (buffer[0] == 0x43 && buffer[1] == 0x4F) {
            buffer.resize(6);
            stream->read(buffer, 6);
            if (buffer[0] == 0x4E && buffer[1] == 0x4E && buffer[2] == 0x45 && buffer[3] == 0x43 && buffer[4] == 0x54)
                return 1;
            return 0;
        }
        return 0;
    }

    inline string socks4To5(const string &socks4) {
        string buffer;
        buffer.resize(10);
        buffer[3] = 0x01;
        for (int i = 4; i < 8; i++) {
            buffer[i] = socks4[i - 2];
        }
        buffer[8] = socks4[0];
        buffer[9] = socks4[1];
        return buffer;
    }

    inline string HttpToSocks5(const string &http) {
        string url = http.substr(0, http.find_first_of(' '));
        string hostname = url.substr(0, url.find_first_of(':'));
        unsigned short port = atoi(url.substr(url.find_first_of(':') + 1).c_str());
        string data;
        data.resize(5 + hostname.length() + 2);
        data[3] = 0x03;
        data[4] = static_cast<char>(hostname.length());
        memcpy(&data[5], hostname.c_str(), hostname.length());
        data[5 + hostname.length()] = static_cast<char>(port >> 8);
        data[5 + hostname.length() + 1] = static_cast<char>(port);
        return data;
    }
}

#endif
