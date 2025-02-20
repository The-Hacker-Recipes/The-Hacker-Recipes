---
authors: ShutdownRepo
category: ad
---

# Network protocols

## Theory

Plaintext protocols (like HTTP, FTP, SNMP, SMTP) are widely used within organizations. Being able to capture and parse that traffic could offer attackers valuable information like sensitive files, passwords or hashes. There are many ways an attacker can obtain a [man-in-the-middle](../../mitm-and-coerced-authentications/) position, [ARP poisoning](../../mitm-and-coerced-authentications/arp-poisoning.md) being the most common and effective one.

## Practice

Once network traffic is hijacked and goes through an attacker-controlled equipement, valuable information can be searched through captured (with [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html), [tshark ](https://www.wireshark.org/docs/man-pages/tshark.html)or [wireshark](https://www.wireshark.org/)) or through live traffic.

[PCredz ](https://github.com/lgandx/PCredz)(Python) is a good example and allows extraction of credit card numbers, NTLM (DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23, i.e. [ASREQroast](../../kerberos/asreqroast.md)), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

```bash
# extract credentials from a pcap file
Pcredz -f "file-to-parse.pcap"

# extract credentials from all pcap files in a folder
Pcredz -d "/path/to/pcaps/"

# extract credentials from a live packet capture on a network interface
Pcredz -i $INTERFACE -v
```

## Resources

[https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz)