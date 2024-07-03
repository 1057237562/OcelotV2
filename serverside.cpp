#include "crypt"
#include "libocelot"
#include "unisocket"
#include <fstream>
#include <iostream>

int main(void)
{
    using namespace unisocket;
    using namespace std;
    using namespace crypto;
    ifstream config;
    config.open("./cfg");
    int cnt;
    config >> cnt;
    vector<string> tokens(cnt);
    for (int i = 0; i < cnt; i++) {
        string username, password;
        config >> username >> password;
        tokens[i] = username + "\n" + password;
    }

    config.close();

    TcpServer server = TcpServer("0.0.0.0", 3060);
    ocelot::OcelotServer ocelot = ocelot::OcelotServer(server, tokens);
    cout << "Server Started!" << endl;
    ocelot.start();
    server.close();
    cout << "Server Down!" << endl;
}