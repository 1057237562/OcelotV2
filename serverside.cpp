#include "crypt"
#include "libocelot"
#include "unisocket"
#include <iostream>

int main(void)
{
    using namespace unisocket;
    using namespace std;
    using namespace crypto;
    init();
    TcpServer server = TcpServer("0.0.0.0", 2080);
    ocelot::OcelotServer ocelot = ocelot::OcelotServer(server, { "libra\n65536forC", "Libra\n65536forC" });
    ocelot.start();
    server.close();
}