#!/bin/bash
rm -rf "$0"
wget -O "$0" "https://github.com/kirin10000/V2Ray-WebSocket-TLS-Web-setup-script/raw/master/V2ray-WebSocket(ws)+TLS(1.3)+Web-setup.sh"
chmod +x "$0"
"$0"
