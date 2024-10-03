#include "crypt"
#include "libocelot"
#include "unisocket"
#include <fstream>
#include <iostream>

int main(int c,char** argv)
{
    using namespace unisocket;
    using namespace std;
    using namespace crypto;
    string cfgpath = "./cfg";
    for(int i = 0; i < c; i ++){
        string arg = string(argv[i],strlen(argv[i]));
        if(arg == "-cfg"){
            cfgpath = string(argv[i+1],strlen(argv[i+1]));
            ++i;
        }
    }

    ifstream config;
    config.open(cfgpath);
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