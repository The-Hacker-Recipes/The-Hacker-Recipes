# ASREQroast

## Theory

The Kerberos authentication protocol works with tickets in order to grant access. A ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to [ASREProast](asreproast.md)).

The pre-authentication requires the requesting user to supply its secret key (DES, RC4, AES128 or AES256) derived from the user password. Technically, when asking the KDC (Key Distribution Center) for a TGT (Ticket Granting Ticket), the requesting user needs to validate pre-authentication by sending a timestamp encrypted with it's own credentials in an `AS_REQ` message. It ensures the user is requesting a TGT for himself. When attackers obtain a **man-in-the-middle** position, they are sometimes able to capture pre-authentication messages, including the encrypted timestamps. Attackers can try to crack those encrypted timestamps to retrieve the user's password.

This technique is similar to [ASREProasting](asreproast.md) but doesn't rely on a misconfiguration. It relies instead on an attacker successfully obtain a powerful enough [man-in-the-middle](../mitm-and-coerced-authentications/) position (i.e. [ARP poisoning](../mitm-and-coerced-authentications/arp-poisoning.md), [ICMP redirect](../mitm-and-coerced-authentications/icmp-redirect.md), [DHCPv6 spoofing](../mitm-and-coerced-authentications/dhcpv6-spoofing.md)).

This technique can be categorized as a [plaintext protocol credential dumping](../credentials/dumping/network-protocols.md) technique.

## Practice

Once network traffic is hijacked and goes through an attacker-controlled equipement, valuable information can searched through captured (with [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html), [tshark ](https://www.wireshark.org/docs/man-pages/tshark.html)or [wireshark](https://www.wireshark.org/)) or through live traffic.

[PCredz ](https://github.com/lgandx/PCredz)(Python) is a good example and allows extraction of credit card numbers, NTLM (DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

```bash
# extract credentials from a pcap file
Pcredz -f "file-to-parse.pcap"

# extract credentials from all pcap files in a folder
Pcredz -d "/path/to/pcaps/"

# extract credentials from a live packet capture on a network interface
Pcredz -i $INTERFACE -v
```

Captured encrypted timestamps can then be cracked with [hashcat](https://hashcat.net/hashcat/) (C), mode 7500.

{% content-ref url="../credentials/cracking.md" %}
[cracking.md](../credentials/cracking.md)
{% endcontent-ref %}

## Resources

{% embed url="https://dumpco.re/blog/asreqroast" %}
