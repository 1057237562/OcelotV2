systemctl stop ocelot
g++ -fdiagnostics-color=always -g serverside.cpp -pthread -lssl -lcrypto -o serverside -std=c++17  -fsanitize=address
chmod 755 serverside
systemctl start ocelot
# -fsanitize=address
