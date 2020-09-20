# IPv6 + DNS poisoning

By default on Windows environments, IPv6 is enabled and has priority over IPv4. Usually, IPv6 is neither used nor configured. When a Windows machine boots or gets plugged in the network, it asks for a IPv6 configuration using DHCPv6. Since DHCPv6 works in multicast, attackers on the same network can answer the DHCPv6 queries and provide the clients with a specific IPv6 config. This is IPv6 poisoning.

The IPv6 config will include a rogue DNS server address. Each client will ask the attacker's server for each domain name resolution. The attacker's server will redirect the clients to other rogue servers that will be able to capture or relay authentications. This is name poisoning.

[mitm6](https://github.com/fox-it/mitm6) \(Python\) can do name poisoning through IPv6 poisoning.

```bash
mitm6 --ignore-nofqdn --interface eth0
```

