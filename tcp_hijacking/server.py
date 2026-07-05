#!/usr/bin/env python3
"""
Multi-Connection TCP Server for NAT Attack Lab
================================================
Accepts multiple simultaneous connections (needed for attack probing).
Runs persistently - no need to restart between tests.

Usage:
    python3 server.py                  # default port 8080
    python3 server.py 9090             # custom port
    python3 server.py 8080 --daemon    # run in background
"""

import socket
import threading
import signal
import sys
import os
import time

DEFAULT_PORT = 8080
connections = []
lock = threading.Lock()
running = True


def handle_client(conn, addr, conn_id):
    """Handle a single client connection."""
    global running
    print(f"[+] [{conn_id}] Connection from {addr[0]}:{addr[1]}")

    with lock:
        connections.append((conn_id, addr, conn))

    try:
        conn.settimeout(1.0)
        while running:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                text = data.decode(errors='replace').strip()
                if text:
                    print(f"    [{conn_id}] {addr[0]}:{addr[1]} -> {text}")
            except socket.timeout:
                continue
            except ConnectionResetError:
                break
            except BrokenPipeError:
                break
            except OSError:
                break
    except Exception as e:
        print(f"[!] [{conn_id}] Error: {e}")
    finally:
        with lock:
            connections[:] = [(i, a, c) for i, a, c in connections if i != conn_id]
        try:
            conn.close()
        except Exception:
            pass
        print(f"[-] [{conn_id}] Disconnected {addr[0]}:{addr[1]}")


def status_display():
    """Show active connection count periodically."""
    global running
    while running:
        time.sleep(30)
        with lock:
            count = len(connections)
        if count > 0:
            print(f"[*] Active connections: {count}")


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global running
    print(f"\n[*] Shutting down server...")
    running = False

    with lock:
        for conn_id, addr, conn in connections:
            try:
                conn.close()
            except Exception:
                pass

    sys.exit(0)


def main():
    global running

    # Parse arguments
    port = DEFAULT_PORT
    daemon = False

    for arg in sys.argv[1:]:
        if arg == "--daemon" or arg == "-d":
            daemon = True
        elif arg == "--help" or arg == "-h":
            print(f"Usage: python3 {sys.argv[0]} [port] [--daemon]")
            print(f"  port     TCP port to listen on (default: {DEFAULT_PORT})")
            print(f"  --daemon Run in background")
            sys.exit(0)
        else:
            try:
                port = int(arg)
            except ValueError:
                print(f"[!] Invalid port: {arg}")
                sys.exit(1)

    # Daemonize if requested
    if daemon:
        pid = os.fork()
        if pid > 0:
            print(f"[*] Server running in background (PID: {pid})")
            sys.exit(0)
        os.setsid()

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create server socket
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        server.settimeout(1.0)
        server.bind(("0.0.0.0", port))
        server.listen(200)
    except OSError as e:
        print(f"[!] Failed to bind port {port}: {e}")
        print(f"    Try: kill $(lsof -t -i:{port}) or use a different port")
        sys.exit(1)

    print(f"{'='*50}")
    print(f"  Multi-Connection TCP Server")
    print(f"  Listening on 0.0.0.0:{port}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*50}")

    # Start status thread
    status_thread = threading.Thread(target=status_display, daemon=True)
    status_thread.start()

    conn_counter = 0

    while running:
        try:
            conn, addr = server.accept()
            conn_counter += 1
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, conn_counter),
                daemon=True
            )
            client_thread.start()
        except socket.timeout:
            continue
        except OSError:
            if running:
                print(f"[!] Socket error, restarting...")
                time.sleep(1)
            break

    server.close()
    print(f"[*] Server stopped. Total connections served: {conn_counter}")


if __name__ == "__main__":
    main()
