from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

# ==========================
# Global Variables
# ==========================

connections = {}

attack_count = 0

WINDOW_SIZE = 1000

print("=" * 60)
print(" Stateful TCP Firewall Started ")
print("=" * 60)


# ==========================
# Helper Functions
# ==========================

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

    print("\n" + "=" * 60)
    print("CONNECTION TABLE")
    print("=" * 60)

    if not connections:
        print("No Active Connections")
        return

    for conn, info in connections.items():

        print(conn)
        print(info)
        print("-" * 60)


def log_attack(ip, tcp, flags):

    global attack_count

    attack_count += 1

    print("\n" + "=" * 60)
    print("[!] ATTACK DETECTED")
    print("=" * 60)

    print(f"Source      : {ip.src}")
    print(f"Destination : {ip.dst}")
    print(f"SPORT       : {tcp.sport}")
    print(f"DPORT       : {tcp.dport}")
    print(f"FLAGS       : {flags}")

    print(f"Total Attacks Blocked : {attack_count}")

    with open("firewall.log", "a") as f:
        f.write(
            f"{ip.src} -> {ip.dst} "
            f"{tcp.sport}->{tcp.dport} "
            f"SEQ={tcp.seq} "
            f"FLAGS={flags} "
            f"DROPPED\n"
        )
# ==========================
# Packet Processing
# ==========================

def process(packet):

    ip = IP(packet.get_payload())

    if TCP not in ip:
        packet.accept()
        return

    tcp = ip[TCP]

    flags = tcp.sprintf("%TCP.flags%")

    print_packet(ip, tcp, flags)

    # -------------------------
    # SYN
    # -------------------------
    if flags == "S":

        key = (
            ip.src,
            ip.dst,
            tcp.sport,
            tcp.dport
        )

        connections[key] = {
            "state": "SYN_SENT",
            "client_seq": tcp.seq,
            "server_seq": 0
        }

        print("\n[+] NEW CONNECTION")
        print(key)

        packet.accept()
        return

    # -------------------------
    # SYN ACK
    # -------------------------
    elif flags == "SA":

        key = (
            ip.dst,
            ip.src,
            tcp.dport,
            tcp.sport
        )

        if key in connections:

            connections[key]["state"] = "SYN_RECEIVED"

            connections[key]["server_seq"] = tcp.seq

            print("\n[+] SYN ACK RECEIVED")

        packet.accept()
        return

    # -------------------------
    # ACK
    # -------------------------
    elif flags == "A":

        key = (
            ip.src,
            ip.dst,
            tcp.sport,
            tcp.dport
        )

        if key in connections:

            connections[key]["state"] = "ESTABLISHED"

            print("\n[+] CONNECTION ESTABLISHED")

            print_connection_table()

        packet.accept()
        return
    
        # -------------------------
    # DATA (PSH / ACK)
    # -------------------------
    elif "P" in flags:

        key = (
            ip.src,
            ip.dst,
            tcp.sport,
            tcp.dport
        )

        reverse_key = (
            ip.dst,
            ip.src,
            tcp.dport,
            tcp.sport
        )

        conn_key = None

        if key in connections:
            conn_key = key

        elif reverse_key in connections:
            conn_key = reverse_key

        # -------------------------
        # Connection Exists
        # -------------------------
        if conn_key and connections[conn_key]["state"] == "ESTABLISHED":

            # Client -> Server
            if key == conn_key:
                expected_seq = connections[conn_key]["client_seq"]

            # Server -> Client
            else:
                expected_seq = connections[conn_key]["server_seq"]

            window_start = expected_seq
            window_end = expected_seq + WINDOW_SIZE

            print("\n" + "=" * 60)
            print("TCP WINDOW CHECK")
            print("=" * 60)

            print(f"Expected SEQ : {expected_seq}")
            print(f"Received SEQ : {tcp.seq}")
            print(f"Window Start : {window_start}")
            print(f"Window End   : {window_end}")

            # -------------------------
            # Invalid Sequence
            # -------------------------
            if not (window_start <= tcp.seq <= window_end):

                print("\n[!] INVALID TCP WINDOW")
                print("[-] Packet Dropped")

                with open("window.log", "a") as f:
                    f.write(
                        f"INVALID "
                        f"{ip.src}->{ip.dst} "
                        f"SEQ={tcp.seq}\n"
                    )

                packet.drop()
                return

            # -------------------------
            # Valid Sequence
            # -------------------------
            print("\n[+] VALID TCP WINDOW")
            print("[+] Packet Forwarded")

            with open("window.log", "a") as f:
                f.write(
                    f"VALID "
                    f"{ip.src}->{ip.dst} "
                    f"SEQ={tcp.seq}\n"
                )

            payload_len = len(bytes(tcp.payload))

            if key == conn_key:
                connections[conn_key]["client_seq"] = tcp.seq + payload_len

            else:
                connections[conn_key]["server_seq"] = tcp.seq + payload_len

            print_connection_table()

            packet.accept()
            return

        # -------------------------
        # No Connection Found
        # -------------------------
        log_attack(ip, tcp, flags)

        print("Reason : NO Established Connection")

        packet.drop()

        return
    # ==========================
# Accept Other Packets
# ==========================

    # Accept all packets that are not explicitly dropped
    packet.accept()


# ==========================
# Main
# ==========================

if __name__ == "__main__":

    # Clear previous logs
    open("firewall.log", "w").close()
    open("window.log", "w").close()

    nfqueue = NetfilterQueue()
    nfqueue.bind(0, process)

    print("\n" + "=" * 60)
    print("Stateful TCP Firewall Running...")
    print("Listening on NFQUEUE 0")
    print("=" * 60)

    try:
        nfqueue.run()

    except KeyboardInterrupt:

        print("\n")
        print("=" * 60)
        print("Stopping Firewall...")
        print("=" * 60)

    finally:
        nfqueue.unbind()