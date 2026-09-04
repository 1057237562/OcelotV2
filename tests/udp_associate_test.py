import socket
import struct
import sys
import time


proxy_port, origin_port = map(int, sys.argv[1:])


def exact(stream: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected SOCKS control EOF")
        data += chunk
    return data


def exchange(udp: socket.socket, relay: tuple[str, int], address: bytes, payload: bytes) -> None:
    udp.sendto(b"\x00\x00\x00" + address + struct.pack("!H", origin_port) + payload, relay)
    response, _ = udp.recvfrom(65535)
    if len(response) < 10 or response[:4] != b"\x00\x00\x00\x01":
        raise RuntimeError("invalid SOCKS UDP response header")
    if response[10:] != payload:
        raise RuntimeError("UDP response payload was corrupted")


control = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
control.sendall(b"\x05\x01\x00")
if exact(control, 2) != b"\x05\x00":
    raise RuntimeError("SOCKS method negotiation failed")
control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
reply = exact(control, 10)
if reply[:4] != b"\x05\x00\x00\x01":
    raise RuntimeError(f"UDP ASSOCIATE failed: {reply.hex()}")

relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0])
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(10)
payload = b"udp-through-the-tunnel"
exchange(udp, relay, b"\x01" + socket.inet_aton("127.0.0.1"), payload)
exchange(udp, relay, b"\x03\x09localhost", payload)
for index in range(100):
    target = (b"\x01" + socket.inet_aton("127.0.0.1")) if index % 2 == 0 else b"\x03\x09localhost"
    exchange(udp, relay, target, f"udp-packet-{index}".encode())
exchange(udp, relay, b"\x01" + socket.inet_aton("127.0.0.1"), bytes(range(256)) * 192)

# Closing the TCP lifetime connection must retire the UDP association.
control.close()
time.sleep(0.5)
udp.settimeout(1)
try:
    udp.sendto(b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1")
               + struct.pack("!H", origin_port) + payload, relay)
    udp.recvfrom(65535)
except (TimeoutError, OSError):
    pass
else:
    raise RuntimeError("UDP association survived its TCP control connection")
finally:
    udp.close()

print(payload.decode())
