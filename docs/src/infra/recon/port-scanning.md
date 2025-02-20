---
authors: ShutdownRepo
category: infra
---

# Port scanning

## Theory

When targeting machines connected to a network, identifying which services are running and accessible remotely allows attackers to have a better understanding of the attack surface.

Services open to the network usually rely on one of two transport protocols: TCP or UDP.

* TCP (Transmission Control Protocol): requires a 3-way handshake to establish a connection. TCP is the most reliable transport protocol of the two as it allows re-transmission of lost data packets.
* UDP (User Datagram Protocol): doesn't require any connection at all. Packets can be sent freely but may not arrive. UDP is faster, simpler, but less reliable. It's mostly used for streaming purposes and for services that have a high speed requirement.

TCP and UDP are quite similar in the sense that they work with ports. Services can be bound to ports and users go through these ports to access the services.

> [!TIP]
> ICMP (Internet Control Message Protocol) is a separate transport protocol that is commonly known for its "echo request" message used to "ping" machines across networks. ICMP doesn't rely on ports like TCP and UDP do. There is no port in ICMP.

While there are many services that are well known for using common ports (e.g. `80/TCP` for HTTP, `443/TCP` for HTTPS, `22/TCP` for SSH, etc.), the port is just a number. Any port from 0 to 65535 can be bound to any service. Machines (a.k.a. hosts) can theoretically have 65536 ports open on TCP, and 65536 ports open on UDP at the same time.

Knowing which ports are open on a host, and which services hide between these ports is essential in the host reconnaissance part of an intrusion attempt.

## Practice

The most commonly used tool for port scanning is [nmap](https://nmap.org/) ("Network Mapper"). This tool features a lot of options but the main ones are the following.

```
SCAN TECHNIQUES
 -sS/sT/sA: TCP SYN/Connect()/ACK scans
 -sU: UDP Scan

PORT SPECIFICATION AND SCAN ORDER
 -p : Only scan specified ports
 Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080
 -F: Fast mode - Scan 100 most common
 --top-ports : Scan  most common ports
 
TIMING AND PERFORMANCE
 -T<0-5>: Set timing template (higher is faster)
 Templates (0-5): paranoid|sneaky|polite|normal|aggressive|insane 

SERVICE/VERSION DETECTION
 -sV: Probe open ports to determine service/version info
 
SCRIPT SCAN
 -sC: equivalent to --script=default

HOST DISCOVERY
 -Pn: Treat all hosts as online -- skip host discovery

FIREWALL/IDS EVASION AND SPOOFING
 -f; --mtu : fragment packets (optionally w/given MTU)
 -S : Spoof source address
 -e : Use specified interface

OUTPUT
 -oN/-oX/-oS/-oG : Output scan in normal, XML, s|: Output in the three major formats at once
 -v: Increase verbosity level (use -vv or more for greater effect)
```

The following nmap commands are the most commonly used.

```bash
# basic TCP SYN scanning of the 1000 most common TCP ports, with a normal speed
nmap $TARGET

# basic TCP SYN scanning of the 100 most common TCP ports, with a normal speed
nmap -F $TARGET

# scan all TCP ports with an aggressive speed, skipping host discovery, adding verbosity
nmap -v -Pn -p "0-65535" -T4 $TARGET

# scan specific TCP ports, enable service/version detection and script scanning, skipping host discovery, with an aggressive speed
nmap -Pn -sC -sV -p "20-25,53,80,135,139,443,445" $TARGET

# same, but scanning known vulnerabilites (CVEs) instead of default scripts
nmap -Pn --script vuln -sV -p "20-25,53,80,135,139,443,445" $TARGET

# scan 20 most common UDP ports and enable service detection
nmap -sU -sV --top-ports 20 $TARGET
```

> [!TIP]
> SCTP (Stream Control Transmission Protocol) is another transport protocol. Its main benfits are high reliability, congestion control and better error handling. This protocol is quite rare but is sometimes used and is worth scanning. Just like TCP and UDP, SCTP works with ports. The `-sY` option can be used in nmap to scan SCTP ports, similarly to `-sU` for UDP.

[MASSCAN](https://github.com/robertdavidgraham/masscan) (C) is an alternative to nmap, mostly known for its speed. Its usage is similar to nmap but focuses essentially on port scanning. Services, versions and scripts scans should be conducted with nmap. Below is an example of masscan being used to scan all TCP and UDP ports of a host with a high rate.

```bash
 masscan -e $INTERFACE -p0-65535,U:0-65535 --max-rate 100000 $TARGETS
```

## Resources

[https://captmeelo.com/pentest/2019/07/29/port-scanning.html](https://captmeelo.com/pentest/2019/07/29/port-scanning.html)