#!/usr/bin/env bash
set -e

# 1) Install system packages
sudo apt update
sudo apt install -y \
  python3-venv python3-pip build-essential libpcap-dev \
  tshark wireshark-common libcap2-bin wireless-tools

# 2) Allow non-root packet capture
echo "→ Adding $USER to wireshark group…"
sudo usermod -aG wireshark "$USER"

# 3) Grant capabilities
echo "→ Granting CAP_NET_RAW,CAP_NET_ADMIN to dumpcap…"
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/dumpcap
echo "   → $(getcap /usr/bin/dumpcap)"

echo "→ Granting CAP_NET_RAW to /usr/bin/python3…"
sudo setcap cap_net_raw+ep /usr/bin/python3
echo "   → $(getcap /usr/bin/python3)"

# 4) Create & activate a virtual environment
echo "→ Creating Python venv in ./venv …"
python3 -m venv venv
source venv/bin/activate

# 5) Install Python libraries
echo "→ Upgrading pip and installing Python packages…"
pip install --upgrade pip
pip install \
  scapy \
  pandas \
  joblib \
  pyshark \
  nfstream

