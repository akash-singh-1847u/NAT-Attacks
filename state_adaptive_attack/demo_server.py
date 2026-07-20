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
ctrl_c_count = 0


def handle_client(conn, addr, conn_id):
    """Handle a single client connection - OLD WORKING VERSION."""
    global running
    print(f"[+] [{conn_id}] Connection from {addr[0]}:{addr[1]} - ESTABLISHED")

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


def signal_handler(sig, frame):
    global ctrl_c_count
    ctrl_c_count += 1

    if ctrl_c_count == 1:
        with lock:
            if not connections:
                print("\n[*] No active connections to FIN.")
            for conn_id, addr, conn in connections:
                try:
                    conn.shutdown(socket.SHUT_WR)
                    print(f"\n[*] FIN sent to [{conn_id}] {addr[0]}:{addr[1]}")
                    print(f"[*] Socket kept open -> client should now be in CLOSE_WAIT (~60s)")
                except Exception as e:
                    print(f"[!] Error: {e}")
        print("[*] Server still running. Press Ctrl+C again to exit.")
    else:
        print("\n[*] Exiting...")
        sys.exit(0)


def main():
    global running
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"[!] Invalid port")
            sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server.settimeout(1.0)
    server.bind(("0.0.0.0", port))
    server.listen(200)

    print("=" * 55)
    print("  Server (keystroke-driven)")
    print(f"  Listening on 0.0.0.0:{port}")
    print("  Idle            -> connections stay ESTABLISHED")
    print("  Ctrl+C (once)   -> FIN all clients, keep socket open (CLOSE_WAIT)")
    print("  Ctrl+C (twice)  -> exit")
    print("=" * 55)

    conn_counter = 0
    while running:
        try:
            conn, addr = server.accept()
            conn_counter += 1
            threading.Thread(target=handle_client, args=(conn, addr, conn_counter), daemon=True).start()
        except socket.timeout:
            continue
        except OSError:
            break

    server.close()
    print("[*] Server stopped.")


if __name__ == "__main__":
    main()