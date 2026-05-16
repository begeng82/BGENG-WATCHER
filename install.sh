#!/bin/bash

echo "[+] Installing BGENG WATCHER"

sudo apt update

sudo apt install python3 python3-pip -y

pip3 install -r requirements.txt

chmod +x BGENG_WATCHER_PRO.py

echo "[+] Installation Complete"

python3 BGENG_WATCHER_PRO.py