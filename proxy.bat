@echo off
cd /d "%~dp0"
set OCELOT_LOG=3
echo Starting OcelotClient proxy: 127.0.0.1:3000 -> 144.168.61.122:4096
.\build-udp\OcelotClient.exe --server 144.168.61.122 --server-port 4096 --listen 3000
pause
