# Off-Path TCP Hijacking Attack on NAT-Enabled Networks

## Overview

This project implements the off-path TCP hijacking attack described in Yang et al., "Off-Path TCP Hijacking Attack to NAT-Enabled Wi-Fi Networks" (IEEE S&P, 2025). The attacker, located on a separate network segment, discovers a client's TCP connection details and hijacks it — injecting data, resetting connections, or taking over sessions — all without being on the network path.

## Topology

```
┌──────────────────┐
│   Attacker VM    │
│   Kali Linux     │
│   30.0.0.30      │
└────────┬─────────┘
         │
    AttackNet (30.0.0.0/24)
         │
┌────────┴─────────────┐
│    NAT Router VM     │
│    Debian 13         │
│  enp0s3: 10.0.0.1    │
│  enp0s8: 20.0.0.1    │
│  enp0s9: 30.0.0.1    │
└──┬────────────────┬──┘
   │                │
PrivateNet      PublicNet
10.0.0.0/24     20.0.0.0/24
   │                │
┌──┴──────┐   ┌────┴─────┐
│ Client  │   │  Server  │
│ Debian  │   │  Debian  │
│10.0.0.10│   │20.0.0.20 │
└─────────┘   └──────────┘
```

## Attack Phases

### Phase 1: Client Port Discovery
The attacker discovers which ephemeral port the client is using for its TCP connection by exploiting NAT port preservation behavior.

### Phase 2: NAT Mapping Eviction & SEQ/ACK Interception
The attacker evicts the client's NAT mapping via brute-force forged RSTs, then steals the port and intercepts the real TCP sequence/acknowledgment numbers via a challenge ACK from the server.

### Phase 3: TCP Hijacking
Using the stolen port and intercepted SEQ/ACK, the attacker injects data, resets the connection, or takes over the session interactively.

---

## Prerequisites

### Router Configuration
```bash
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Disable strict TCP window tracking
sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1

# Disable reverse path filtering
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0

# NAT masquerade via nftables
# nft add table ip nat
# nft add chain ip nat postrouting { type nat hook postrouting priority srcnat \; policy accept \; }
# nft add rule ip nat postrouting oifname "enp0s8" masquerade
```

### Client Configuration
```bash
# Reduce ephemeral port range for faster scanning in lab
sysctl -w net.ipv4.ip_local_port_range="50000 50010"
```

### Server Setup
```bash
python3 server.py
```

### Attacker Requirements
- Python 3 with Scapy installed
- Root access (required for raw socket operations)

---

## Step-by-Step Attack Guide

### Step 1: Establish Victim Connection

**Server (20.0.0.20):**
```bash
python3 server.py
```

**Client (10.0.0.10):**
```bash
nc 20.0.0.20 8080
```
Leave the connection idle — do not type anything.

**Router — verify the NAT mapping exists:**
```bash
conntrack -L -p tcp --dport 8080
```

---

### Step 2: Phase 1 — Discover Client's Source Port

**On Attacker (Kali):**
```bash
# Full automatic scan
sudo python3 phase1_port_inference.py

# Or validate a known port first
sudo python3 phase1_port_inference.py --test <port>
```

**Expected output:**
```
==================================================
  CLIENT PORT: 50006
  Found in 8.2 seconds
==================================================
```

---

### Step 3: Phase 2+3 — Evict, Intercept, and Attack

**On Attacker (Kali):**
```bash
sudo python3 phase2_and_3.py <client_port>
```

This script:
1. Sends 65,536 forged RSTs covering the entire 32-bit seq space
2. Sends PUSH/ACK to steal the port and capture challenge ACK
3. Opens interactive attack console

**Attack Console Commands:**

| Command | Description |
|---------|-------------|
| `inject <text>` | Inject data into the TCP stream |
| `reset` | Send RST to kill the connection |
| `inject_reset <text>` | Inject data then kill connection |
| `hijack` | Interactive mode — type messages continuously |
| `quit` | Exit |

**Example session:**
```
[attack]> inject HACKED BY ATTACKER
[+] Injected: HACKED BY ATTACKER

[attack]> reset
[+] RST sent! Connection killed.
```

**Server confirms the attack:**
```
    [1] 20.0.0.1:50006 -> HACKED BY ATTACKER
[-] [1] Disconnected 20.0.0.1:50006
```

---

## How Each Phase Works

### Phase 1: Port Inference via NAT Port Preservation

NAT routers try to preserve the client's source port. When the attacker sends a SYN using a guessed port:

- **FREE port:** NAT preserves it for the attacker. A spoofed SYN/ACK with marker seq (0xDEADBEEF) returns to attacker.
- **CLIENT port:** NAT assigns a different port. The marker goes to the client instead.

By checking whether the marker returns, the attacker identifies the client's port. Majority voting (6/7) eliminates false positives.

### Phase 2: NAT Mapping Eviction via Brute-Force RST

The attacker sends forged RST packets (spoofed as the server) to the NAT router. Linux conntrack validates RST sequence numbers against the TCP window (~65,535 bytes). The attacker sends 65,536 RSTs spaced by window size to cover the entire 2^32 space. One lands in the valid window, deleting the mapping.

Consumer routers without TCP state tracking can be evicted with a single forged RST.

### Phase 2 (continued): SEQ/ACK Interception via Challenge ACK

After eviction, the attacker sends PUSH/ACK using the client's former port. The NAT creates a new mapping for the attacker. The server receives out-of-window data and responds with a challenge ACK (RFC 5961) containing real SEQ/ACK. The NAT forwards this to the attacker.

### Phase 3: TCP Injection / Reset / Hijack

With correct port + SEQ/ACK:
- **Inject:** PSH/ACK with seq=server_ACK, ack=server_SEQ
- **Reset:** RST with seq=server_ACK (advances after each injection)
- **Hijack:** Continuous injection with auto-incrementing sequence numbers

---

## File Descriptions

| File | Location | Description |
|------|----------|-------------|
| `server.py` | Server VM `/root/` | Multi-connection TCP server on port 8080 |
| `phase1_port_inference.py` | Attacker VM `~/` | Discovers client's port via NAT port preservation probing |
| `phase2_and_3.py` | Attacker VM `~/` | Combined: brute-force RST eviction + challenge ACK interception + attack console |

---

## Vulnerabilities Exploited

| Vulnerability | How Exploited |
|---------------|---------------|
| NAT port preservation | Attacker detects port conflicts to identify client's port |
| No reverse path validation (rp_filter=0) | Spoofed packets pass through the router |
| TCP challenge ACK (RFC 5961) | Server leaks real SEQ/ACK to off-path attacker |
| NAT mapping eviction via RST | Forged RSTs delete client's mapping so attacker can steal the port |
| Liberal TCP tracking (tcp_be_liberal=1) | Router accepts packets without strict TCP state validation |

---

## Defenses

| Defense | Effect |
|---------|--------|
| Enable reverse path filtering (rp_filter=1) | Blocks spoofed packets at the router |
| Disable NAT port preservation | Randomizes external ports, making inference infeasible |
| Strict TCP window tracking | Rejects forged RSTs with out-of-window sequence numbers |
| Encrypted protocols (TLS/SSH) | Injected data rejected at application layer |
| Randomize challenge ACK rate limiting | Prevents SEQ/ACK inference via challenge ACKs |

---

## References

1. Yang et al., "Off-Path TCP Hijacking Attack to NAT-Enabled Wi-Fi Networks," IEEE S&P, 2025.
2. Feng et al., "Off-Path TCP Hijacking Attacks via the Side Channel of Downgraded IPID," IEEE/ACM ToN, 2022.
3. Qian and Mao, "Off-Path TCP Sequence Number Inference Attack," IEEE S&P, 2012.
4. Feng and Chen, "An Internet-wide Penetration Study on NAT Boxes via TCP/IP Side Channel," IEEE S&P, 2023.
5. RFC 5961 — Improving TCP's Robustness to Blind In-Window Attacks.
6. RFC 2663 — IP Network Address Translator (NAT) Terminology and Considerations.
