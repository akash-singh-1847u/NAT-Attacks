#!/usr/bin/env python3
"""
Simple server on Public VM (20.0.0.20)
Listens for connections and prints received data
"""

import socket
import threading

HOST = "0.0.0.0"
PORT = 8080

def handle_client(conn, addr):
    """Handle individual client connection"""
    print(f"\n[+] Client connected: {addr}")
    
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            
            print(f"[+] Data received from {addr}:")
            print(f"    {data.decode()}")
            
            # Send response
            conn.send(b"Data received\n")
    
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()
        print(f"[-] Client disconnected: {addr}")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print("=" * 60)
    print(f"  Server listening on {HOST}:{PORT}")
    print("=" * 60)
    
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
    
    except KeyboardInterrupt:
        print("\n[*] Server shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
