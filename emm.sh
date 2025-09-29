wget https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz -O xmrig.tar.gz
tar -zxvf xmrig.tar.gz
mv xmrig* emm
mv emm/xmrig emm/emm
cp config.json xmrig/config.json
./emm/emm
