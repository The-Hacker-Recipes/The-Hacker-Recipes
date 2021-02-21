# DHCPv6 spoofing

By default on Windows environments, IPv6 is enabled and has priority over IPv4. Usually, IPv6 is neither used nor configured. When a Windows machine boots or gets plugged in the network, it asks for a IPv6 configuration using DHCPv6. Since DHCPv6 works in multicast, attackers on the same network can answer the DHCPv6 queries and provide the clients with a specific IPv6 config. This is IPv6 poisoning.

The IPv6 config will include a rogue DNS server address \(actually it will include two addresses, one IPv4 and one IPv6\). Each client will then query the attacker's server for every domain name resolution. The attacker's server will redirect the clients to other rogue applicative servers that will be able to capture or relay authentications. This is DNS poisoning through DHCPv6 spoofing.

[mitm6](https://github.com/fox-it/mitm6) \(Python\) can do DNS poisoning through DHCPv6 spoofing.

```bash
mitm6 --interface eth0 --domain $DOMAIN
```

This technique can be used as a powerful helper for [WPAD abuse](wpad-spoofing.md).

