# Stateful TCP Firewall with NAT and TCP Sequence Number Validation

## Overview

This project implements a **Stateful TCP Firewall** running on a NAT Router. The firewall monitors TCP connections, maintains a connection table, validates TCP sequence numbers, and detects spoofed TCP packets attempting to bypass connection tracking.

The project demonstrates how a stateful firewall protects established TCP connections from unauthorized packets and serves as a foundation for studying **Off-Path TCP Sequence Number Inference Attacks**.

---

## Features

- Stateful TCP Connection Tracking
- TCP Three-Way Handshake Monitoring
- NAT Router Integration
- TCP Window Validation
- TCP Sequence Number Verification
- Detection of Spoofed TCP Packets
- Attack Logging
- Connection State Management
- Scapy-based Packet Injection
- Firewall Logging and Debugging

---

## Network Topology

```
                 Attacker
              (30.0.0.30)
                    |
                    |
          -----------------------
          |     NAT Router      |
          | Stateful Firewall   |
          -----------------------
          |                     |
      Client                 Server
   (10.0.0.10)            (20.0.0.20)
```

---

## Components

### Client

- Establishes TCP connection
- Sends application data
- Maintains active TCP session

---

### Server

- Accepts TCP connections
- Receives client messages
- Responds to valid requests

---

### NAT Router

- Performs Network Address Translation
- Routes packets between networks
- Hosts the Stateful Firewall

---

### Stateful Firewall

The firewall maintains a connection table containing:

- Source IP
- Destination IP
- Source Port
- Destination Port
- TCP State
- Client Sequence Number
- Server Sequence Number

Supported TCP states include:

- SYN_SENT
- SYN_RECEIVED
- ESTABLISHED

---

## Firewall Processing

For every incoming TCP packet:

1. Identify TCP flow
2. Verify connection exists
3. Validate TCP state
4. Perform TCP Window Check
5. Forward valid packets
6. Drop invalid packets
7. Log attack attempts

---

## TCP Window Validation

The firewall verifies whether the received TCP sequence number falls within the valid receive window.

```
Window Start <= TCP Sequence <= Window End
```

Packets outside the valid window are immediately dropped.

---

## Connection Table Example

```
(10.0.0.10, 20.0.0.20, 35776, 8080)

State        : ESTABLISHED
Client SEQ   : 3276376749
Server SEQ   : 2523698453
```

---

## Attack Simulation

A Scapy-based attacker generates spoofed TCP packets using:

- Spoofed Client IP
- Correct TCP Ports
- Guessed TCP Sequence Numbers

Example:

```
Trying SEQ : 2523698400
Trying SEQ : 2523698410
Trying SEQ : 2523698420
...
```

The firewall evaluates each packet against the active TCP connection.

---

## Attack Detection

The firewall detects:

- Packets without an established connection
- Invalid TCP sequence numbers
- Packets outside the TCP receive window
- Unauthorized spoofed packets

Example output:

```
TCP WINDOW CHECK

INVALID TCP WINDOW

Packet Dropped
```

or

```
VALID TCP WINDOW

Packet Forwarded
```

---

## Technologies Used

- Python 3
- Scapy
- NetfilterQueue
- nftables
- Linux Networking
- VirtualBox
- Debian
- Kali Linux

---

## Future Work

This project serves as a foundation for implementing:

- TCP Sequence Number Inference
- Off-Path TCP Attacks
- Side-Channel Analysis
- IPID-based Sequence Inference
- Timing-based Inference
- Automated TCP Sequence Search

---

## Learning Outcomes

- TCP Three-Way Handshake
- Stateful Firewall Design
- NAT Configuration
- TCP Sequence Number Validation
- TCP Receive Window
- Connection Tracking
- Packet Inspection
- Spoofed Packet Detection
- TCP Attack Simulation

---

## Disclaimer

This project is developed strictly for cybersecurity research, network security education, and academic purposes. All experiments were performed inside an isolated virtual network.