#include "crypt"
#include "libocelot"
#include "unisocket"
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
    ocelot::OcelotServer ocelot = ocelot::OcelotServer(server, { "libra\n65536forC","Libra\n65536forC","Stewie\njerky" });
    cout<<"Server Started!"<<endl;
    ocelot.start();
    server.close();
    cout<<"Server Down!"<<endl;
}