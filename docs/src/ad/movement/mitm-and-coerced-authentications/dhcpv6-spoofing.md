---
authors: ShutdownRepo
category: ad
---

# DHCPv6 spoofing

## Theory

### DHCPv6 spoofing and poisoning

By default on Windows environments, IPv6 is enabled and has priority over IPv4. Usually, IPv6 is neither used nor configured. When a Windows machine boots or gets plugged in the network, it asks for an IPv6 configuration through a DHCPv6 request. Since DHCPv6 works in multicast, attackers on the same network can answer the DHCPv6 queries and provide the clients with a specific IP config. The IP config will include a rogue DNS server address (actually, for [mitm6](https://github.com/fox-it/mitm6), it will include two addresses, one IPv4 and one IPv6). This technique is called DHCPv6 spoofing.

It is worth to note that DHCPv6 spoofing can be particularly useful for carrying [Kerberos relay](../kerberos/relay.md#abuse-from-dns-poisoning) attacks.

### DNS spoofing

Attackers can then proceed to [DNS spoofing](dns-spoofing.md). Once the clients DNS servers are set through the fake IP config pushed through DHCPv6 spoofing, each client will query the attacker's server for every domain name resolution. The attacker's server will redirect the clients to other rogue servers that will be able to capture or relay authentications.

## Practice

> [!WARNING]
> Combining DHCPv6 spoofing with DNS spoofing can cause temporary but severe disruption in the network. It is highly recommended to target specific addresses and machines.

[mitm6](https://github.com/fox-it/mitm6) (Python) is an all-in-one tool for DHCPv6 spoofing + DNS poisoning. The following command can be run to make mitm6 redirect internal traffic only.

```bash
mitm6 --interface eth0 --domain $DOMAIN_FQDN
```

[bettercap](https://www.bettercap.org/) (Go) can also be used for DHCPv6 spoofing and [DNS spoofing](dns-spoofing.md).

```bash
# Configure and start DHCPv6 spoofing
set dhcp6.spoof.domains $DOMAIN_FQDN
dhcp6.spoof on

# Configure and DNS DHCPv6 spoofing
set dns.spoof.domains $DOMAIN_FQDN
set dns.spoot.all true
dns.spoof on
```

## Resources

[https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)

[https://www.bettercap.org/modules/ethernet/spoofers/dhcp6.spoof/](https://www.bettercap.org/modules/ethernet/spoofers/dhcp6.spoof/)