#!/bin/bash
set -e

echo "[+] Installing Mini-SOC"

apt update
apt install -y python3 python3-venv git

id mini-soc &>/dev/null || useradd -r -s /usr/sbin/nologin mini-soc
usermod -aG adm mini-soc

mkdir -p /opt/mini-soc
cp -r . /opt/mini-soc
cd /opt/mini-soc

python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

chown -R mini-soc:adm /opt/mini-soc
chmod -R 750 /opt/mini-soc

cp deploy/mini-soc.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable mini-soc
systemctl start mini-soc

echo "[✓] Mini-SOC installed and running"
