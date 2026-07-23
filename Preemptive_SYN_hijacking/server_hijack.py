#!/usr/bin/env python3
# Server VM (20.0.0.20) - Simple TCP server on port 8080

import socket
import threading

def handle(conn, addr):
    print("[+] Connected: " + str(addr))
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print("[+] " + str(addr) + " -> " + data.decode(errors="replace").strip())
            conn.send(b"OK\n")
    except:
        pass
    conn.close()
    print("[-] Disconnected: " + str(addr))

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8080))
    s.listen(5)
    print("=" * 50)
    print("  Server listening on 0.0.0.0:8080")
    print("=" * 50)
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Stopped")
    s.close()

if __name__ == "__main__":
    main()