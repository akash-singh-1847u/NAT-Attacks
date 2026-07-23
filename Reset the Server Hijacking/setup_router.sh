#!/bin/bash
# Run this on the ROUTER VM before starting firewall.py
# Ensures ALL forwarded TCP goes through NFQUEUE (no conntrack bypass)

echo "[*] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

echo "[*] Flushing ALL iptables rules..."
iptables -F              # flush filter table
iptables -t nat -F       # flush NAT table
iptables -t mangle -F    # flush mangle table
iptables -t raw -F       # flush raw table

echo "[*] Setting FORWARD policy to DROP..."
iptables -P FORWARD DROP

echo "[*] Adding NFQUEUE rule for TCP..."
iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 0

echo "[*] Allowing non-TCP traffic..."
iptables -A FORWARD ! -p tcp -j ACCEPT

echo ""
echo "[*] Verifying rules:"
iptables -L FORWARD -v -n
echo ""
echo "[*] Verifying NO NAT:"
iptables -t nat -L -n
echo ""
echo "[+] Done. Now run: sudo python3 firewall.py"
