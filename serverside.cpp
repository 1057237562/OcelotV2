#include "crypt.hpp"
#include "libocelot.hpp"
#include "unisocket.hpp"
#include <iostream>

int main(void)
{
    using namespace unisocket;
    using namespace std;
    using namespace crypto;
    #ifdef _WIN32
    init();
    #endif
    TcpServer server = TcpServer("0.0.0.0", 3060);
    ocelot::OcelotServer ocelot = ocelot::OcelotServer(server, { "libra\n65536forC","Libra\n65536forC" });
    cout<<"Server Started!"<<endl;
    ocelot.start();
    server.close();
    cout<<"Server Down!"<<endl;
}
