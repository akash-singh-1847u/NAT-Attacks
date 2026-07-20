import socket
import sys
import struct
import signal
import time


sock = None
graceful_done = False


def graceful_close(sig, frame):
    global graceful_done
    if graceful_done:
        return
    graceful_done = True
    print("\n[Ctrl+C] Sending graceful close (normal FIN) -> TIME_WAIT (~120s)")
    try:
        sock.close()
    except Exception as e:
        print(f"Error: {e}")
    sys.exit(0)


def rst_close(sig, frame):
    global graceful_done
    if graceful_done:
        return
    graceful_done = True
    print("\n[Ctrl+\\] Sending RST -> CLOSE (~10s)")
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()
    except Exception as e:
        print(f"Error: {e}")
    sys.exit(0)


def main():
    global sock
    server_ip = sys.argv[1] if len(sys.argv) > 1 else "20.0.0.20"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    local_port = sock.getsockname()[1]

    print(f"PORT={local_port}")
    print("Connected - ESTABLISHED")
    print()
    print("  Idle            -> stays ESTABLISHED (also survives server's FIN -> CLOSE_WAIT)")
    print("  Ctrl+C          -> graceful close -> TIME_WAIT (~120s)")
    print("  Ctrl+\\ (backslash) -> abrupt RST close -> CLOSE (~10s)")
    print()
    print("Just leave this running and idle for ESTABLISHED / CLOSE_WAIT tests.")

    signal.signal(signal.SIGINT, graceful_close)
    signal.signal(signal.SIGQUIT, rst_close)

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
