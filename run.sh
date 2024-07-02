cowsay "777 is bad, don't do that ever again"
systemctl stop ocelot
g++ -fdiagnostics-color=always -g serverside.cpp -pthread -lssl -lcrypto -o serverside -std=c++17
chmod 777 serverside
systemctl start ocelot
# -fsanitize=address
