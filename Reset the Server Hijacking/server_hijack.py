#!/usr/bin/env python3
import socket, threading

def handle(conn, addr):
    print(f"[+] Connected: {addr}")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[+] {addr} → {data.decode(errors='replace').strip()}")
            conn.send(b"OK\n")
    except:
        pass
    conn.close()
    print(f"[-] Disconnected: {addr}")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8080))
s.listen(5)
print("Server listening on 0.0.0.0:8080")
try:
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
except KeyboardInterrupt:
    print("\nStopped")
s.close()
